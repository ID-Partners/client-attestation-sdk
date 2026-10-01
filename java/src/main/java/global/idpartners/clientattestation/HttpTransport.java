/*
 * The one outbound HTTP path for the SDK. Every call site goes through here so they all get the same
 * safety properties: a request timeout on every call, a connect timeout on every client, redirects never
 * followed (requests carry credentials — Authorization, DPoP, attestation headers, X-Vault-Token, SVIDs in
 * bodies — that must not be replayed to wherever a Location header points), and a response-body cap that
 * is enforced while the body streams in rather than after buffering it.
 */
package global.idpartners.clientattestation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.jose4j.json.JsonUtil;

/** Package-private transport helper shared by every outbound HTTP call in the SDK. */
final class HttpTransport {

    /** Default response-body cap: 1 MiB. */
    static final long DEFAULT_MAX_BYTES = 1L << 20;
    /** At most this many characters of a response body are quoted in an error message. */
    static final int ERROR_BODY_CHARS = 512;

    private HttpTransport() {
    }

    /** A completed exchange. {@code body} is the UTF-8 decoded response (never null). */
    record Response(int status, HttpHeaders headers, String body) {
        boolean ok() {
            return this.status >= 200 && this.status < 300;
        }
    }

    /** A client with a connect timeout that never follows redirects. */
    static HttpClient client(Duration connectTimeout) {
        return HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Send {@code req} with a request timeout of {@code timeout} (which also bounds reading the body) and
     * a body cap of {@code maxBytes}. Non-2xx responses are returned, not thrown — callers decide what an
     * error body means. A 3xx is refused with a {@link TransportException}; so are I/O failures,
     * timeouts, interruption (the interrupt flag is restored) and oversize bodies.
     */
    static Response send(HttpClient client, HttpRequest.Builder req, Duration timeout, long maxBytes) {
        HttpRequest request = req.timeout(timeout).build();
        String what = request.method() + " " + request.uri();
        CompletableFuture<HttpResponse<byte[]>> future =
                client.sendAsync(request, info -> new CappedSubscriber(info, maxBytes));
        HttpResponse<byte[]> resp;
        try {
            // The request timeout covers the response headers; this deadline also covers the body.
            resp = future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new TransportException("Interrupted during " + what, 0, null, e);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new TransportException(what + " timed out after " + timeout.toMillis() + "ms", 0, null, e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            if (cause instanceof BodyTooLargeException) {
                throw new TransportException(what + " response body exceeds " + maxBytes + " bytes", 0, null,
                        cause);
            }
            if (cause instanceof HttpTimeoutException) {
                throw new TransportException(what + " timed out after " + timeout.toMillis() + "ms", 0, null,
                        cause);
            }
            throw new TransportException(what + " failed: " + cause, 0, null, cause);
        }
        int status = resp.statusCode();
        if (status >= 300 && status < 400) {
            String location = resp.headers().firstValue("location").orElse("(none)");
            throw new TransportException(what + " returned redirect HTTP " + status + " to " + location
                    + "; redirects are not followed", status, null);
        }
        byte[] body = resp.body() != null ? resp.body() : new byte[0];
        return new Response(status, resp.headers(), new String(body, StandardCharsets.UTF_8));
    }

    /** As {@link #send(HttpClient, HttpRequest.Builder, Duration, long)} with the default 1 MiB cap. */
    static Response send(HttpClient client, HttpRequest.Builder req, Duration timeout) {
        return send(client, req, timeout, DEFAULT_MAX_BYTES);
    }

    /** The response's JSON object; throws {@link TransportException} for non-2xx or a non-object body. */
    static Map<String, Object> jsonOk(Response r) {
        if (!r.ok()) {
            String quoted = truncate(r.body());
            throw new TransportException("HTTP " + r.status() + ": " + quoted, r.status(), quoted);
        }
        return parseObject(r.body(), r.status());
    }

    /** Parse a JSON object, mapping any parse failure or non-object document to {@link TransportException}. */
    static Map<String, Object> parseObject(String text, int status) {
        Map<String, Object> parsed;
        try {
            parsed = JsonUtil.parseJson(text);
        } catch (Exception e) {
            // JoseException for malformed JSON; ClassCastException when the document is not an object.
            throw new TransportException("response is not a JSON object: " + truncate(text), status,
                    truncate(text), e);
        }
        if (parsed == null) {
            throw new TransportException("response is not a JSON object: " + truncate(text), status,
                    truncate(text));
        }
        return parsed;
    }

    /** At most {@link #ERROR_BODY_CHARS} characters of {@code s}. */
    static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= ERROR_BODY_CHARS ? s : s.substring(0, ERROR_BODY_CHARS) + "...";
    }

    /** Signals the cap was exceeded; never escapes this class. */
    private static final class BodyTooLargeException extends IOException {
        BodyTooLargeException() {
            super("response body too large");
        }
    }

    /** Buffers the body up to {@code max} bytes and fails (cancelling the stream) the moment it exceeds it. */
    private static final class CappedSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final long max;
        private final boolean declaredTooLarge;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        private long received;

        CappedSubscriber(HttpResponse.ResponseInfo info, long max) {
            this.max = max;
            this.declaredTooLarge = info.headers().firstValueAsLong("content-length").orElse(-1L) > max;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            this.subscription = s;
            if (this.declaredTooLarge) {
                s.cancel();
                this.result.completeExceptionally(new BodyTooLargeException());
                return;
            }
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (this.result.isDone()) {
                return;
            }
            for (ByteBuffer item : items) {
                this.received += item.remaining();
                if (this.received > this.max) {
                    this.subscription.cancel();
                    this.result.completeExceptionally(new BodyTooLargeException());
                    return;
                }
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                this.buffer.write(chunk, 0, chunk.length);
            }
        }

        @Override
        public void onError(Throwable t) {
            this.result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            this.result.complete(this.buffer.toByteArray());
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return this.result;
        }
    }
}
