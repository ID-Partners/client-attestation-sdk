/*
 * The one outbound HTTP path for the SDK. Every call site goes through here so they all get the same
 * safety properties: a request timeout on every call, a connect timeout on every client, redirects never
 * followed (requests carry credentials — Authorization, DPoP, attestation headers, X-Vault-Token, SVIDs in
 * bodies — that must not be replayed to wherever a Location header points), and a response-body cap that
 * is enforced while the body streams in rather than after buffering it.
 *
 * Proxies follow the rule every port shares: a request goes through a proxy only when it is https to a host
 * that is not loopback, link-local or a cloud metadata server, and then only through the JVM's own proxy
 * settings ({@code https.proxyHost}, or the system proxies with {@code java.net.useSystemProxies}), as a
 * CONNECT tunnel that keeps TLS end to end. Plain http always goes direct: an OpenBao X-Vault-Token or a
 * metadata identity token would cross a proxy in cleartext. A URL with userinfo ({@code user:password@}) is
 * refused, and errors name a URL without its userinfo or query.
 */
package global.idpartners.clientattestation.internal;

import global.idpartners.clientattestation.TransportException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.jose4j.json.JsonUtil;

/**
 * The transport helper shared by every outbound HTTP call in the SDK, including the
 * {@code tokenvalidator} package.
 *
 * <p><b>Not API.</b> This package is internal: it is public only so the SDK's own packages can share it,
 * it is not exported by the module, and it may change in any release.
 */
public final class HttpTransport {

    /** Default response-body cap: 1 MiB. */
    public static final long DEFAULT_MAX_BYTES = 1L << 20;
    /**
     * At most this many characters of a non-2xx response body are quoted in an error. A 2xx body is never
     * quoted or kept: that is where access tokens, attestations and SVIDs travel.
     */
    public static final int ERROR_BODY_CHARS = 512;

    private HttpTransport() {
    }

    /**
     * A completed exchange. {@code body} is the UTF-8 decoded response (never null).
     *
     * @param status  the HTTP status
     * @param headers the response headers
     * @param body    the decoded response body
     */
    public record Response(int status, HttpHeaders headers, String body) {
        /**
         * Whether the status is 2xx.
         *
         * @return true for a 2xx status
         */
        public boolean ok() {
            return this.status >= 200 && this.status < 300;
        }
    }

    /** Cloud metadata servers that aren't link-local addresses (169.254.169.254 is caught as link-local). */
    private static final Set<String> METADATA_HOSTS = Set.of("metadata.google.internal", "metadata", "fd00:ec2::254");

    /**
     * The SDK's proxy rule: the JVM's default selector for https to a host {@link #neverProxied} allows,
     * and no proxy for anything else.
     */
    static final ProxySelector SDK_PROXIES = new ProxySelector() {
        @Override
        public List<Proxy> select(URI uri) {
            ProxySelector base = ProxySelector.getDefault();
            if (base == null || !"https".equalsIgnoreCase(uri.getScheme()) || neverProxied(uri.getHost())) {
                return List.of(Proxy.NO_PROXY);
            }
            return base.select(uri);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress address, IOException e) {
            ProxySelector base = ProxySelector.getDefault();
            if (base != null) {
                base.connectFailed(uri, address, e);
            }
        }
    };

    /**
     * Whether {@code host} is loopback, link-local or a cloud metadata server: the SDK sends those hosts
     * tokens it must not route anywhere else. Never resolves a name.
     *
     * @param host a host name or IP literal (IPv6 with or without brackets)
     * @return true when the host must never be reached through a proxy
     */
    public static boolean neverProxied(String host) {
        if (host == null) {
            return false;
        }
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.equals("localhost") || h.endsWith(".localhost") || METADATA_HOSTS.contains(h)) {
            return true;
        }
        int zone = h.indexOf('%');
        if (zone >= 0) {
            h = h.substring(0, zone);
        }
        // only literals: getByName would otherwise look the name up
        if (!h.contains(":") && !h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(h);
            return address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isAnyLocalAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * {@code uri} without its userinfo, query or fragment, for error messages: a query can carry a secret,
     * and userinfo is one.
     *
     * @param uri the URI
     * @return the URI as shown in an error
     */
    public static String display(URI uri) {
        String authority = uri.getRawAuthority();
        String host = authority == null ? "" : authority.substring(authority.lastIndexOf('@') + 1);
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        return uri.getScheme() + "://" + host + path;
    }

    /**
     * A client with a connect timeout that never follows redirects, using the SDK's proxy rule.
     *
     * @param connectTimeout the connect timeout
     * @return the client
     */
    public static HttpClient client(Duration connectTimeout) {
        return HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(SDK_PROXIES)
                .build();
    }

    /**
     * Send {@code req} with a request timeout of {@code timeout} (which also bounds reading the body) and
     * a body cap of {@code maxBytes}. Non-2xx responses are returned, not thrown — callers decide what an
     * error body means. A 3xx is refused with a {@link TransportException}; so are I/O failures,
     * timeouts, interruption (the interrupt flag is restored) and oversize bodies.
     *
     * @param client   the client to send with
     * @param req      the request to send
     * @param timeout  the request timeout, which also bounds reading the body
     * @param maxBytes the response-body cap
     * @return the response
     * @throws TransportException on any transport failure
     */
    public static Response send(HttpClient client, HttpRequest.Builder req, Duration timeout, long maxBytes) {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("credential requests require HttpClient.Redirect.NEVER");
        }
        HttpRequest request = req.timeout(timeout).build();
        String what = request.method() + " " + display(request.uri());
        String authority = request.uri().getRawAuthority();
        if (authority != null && authority.contains("@")) {
            throw new TransportException(what + ": URLs with userinfo (user:password@) are not supported", 0, null);
        }
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

    /**
     * As {@link #send(HttpClient, HttpRequest.Builder, Duration, long)} with the default 1 MiB cap.
     *
     * @param client  the client to send with
     * @param req     the request to send
     * @param timeout the request timeout
     * @return the response
     * @throws TransportException on any transport failure
     */
    public static Response send(HttpClient client, HttpRequest.Builder req, Duration timeout) {
        return send(client, req, timeout, DEFAULT_MAX_BYTES);
    }

    /**
     * The response's JSON object.
     *
     * @param r the response
     * @return the parsed object
     * @throws TransportException for a non-2xx status or a body that is not a JSON object
     */
    public static Map<String, Object> jsonOk(Response r) {
        if (!r.ok()) {
            String quoted = truncate(r.body());
            throw new TransportException("HTTP " + r.status() + ": " + quoted, r.status(), quoted);
        }
        return parseObject(r.body(), r.status());
    }

    /**
     * The body of a 2xx response.
     *
     * @param r the response
     * @return the body
     * @throws TransportException for a non-2xx status
     */
    public static String textOk(Response r) {
        if (!r.ok()) {
            String quoted = truncate(r.body());
            throw new TransportException("HTTP " + r.status() + ": " + quoted, r.status(), quoted);
        }
        return r.body();
    }

    /**
     * The {@code reason} attribute docs/logging.md gives a failed call: {@code timeout}, {@code redirect},
     * {@code too_large}, {@code status} (a non-2xx answer), {@code malformed} (a 2xx answer that is not the
     * JSON expected) or {@code network}.
     *
     * @param e the failure
     * @return the reason
     */
    public static String failureReason(Throwable e) {
        if (!(e instanceof TransportException)) {
            return "network";
        }
        TransportException te = (TransportException) e;
        Throwable cause = te.getCause();
        if (cause instanceof TimeoutException || cause instanceof HttpTimeoutException) {
            return "timeout";
        }
        if (te.status() >= 300 && te.status() < 400) {
            return "redirect";
        }
        if (String.valueOf(te.getMessage()).contains("response body exceeds")) {
            return "too_large";
        }
        if (te.status() >= 200 && te.status() < 300) {
            return "malformed";
        }
        return te.status() > 0 ? "status" : "network";
    }

    /**
     * Parse a JSON object, mapping any parse failure or non-object document to {@link TransportException}.
     * The exception neither quotes nor keeps {@code text}, and has no cause.
     *
     * @param text   the document
     * @param status the HTTP status it came with, carried by the exception
     * @return the parsed object
     * @throws TransportException when {@code text} is not a JSON object
     */
    public static Map<String, Object> parseObject(String text, int status) {
        Map<String, Object> parsed;
        try {
            parsed = JsonUtil.parseJson(text);
        } catch (Exception e) {
            // JoseException for malformed JSON; ClassCastException when the document is not an object. The
            // parser's message can quote the document (a whole token, for a trailing string), so it isn't
            // chained: the body this parses is a 2xx one, which carries tokens, attestations and SVIDs.
            throw new TransportException("response is not a JSON object", status, null);
        }
        if (parsed == null) {
            throw new TransportException("response is not a JSON object", status, null);
        }
        return parsed;
    }

    /**
     * A {@link TransportException} for a 2xx response whose body is not what the caller expected, for a
     * caller that parses the body itself.
     *
     * @param message what was wrong (never quoting the body)
     * @param status  the HTTP status
     * @return the exception, for the caller to throw
     */
    public static TransportException malformed(String message, int status) {
        return new TransportException(message, status, null);
    }

    /**
     * The first {@link #ERROR_BODY_CHARS} characters of {@code s} (all of it when shorter), with no marker
     * appended: an exposed body is always a prefix of the response, as in the other ports.
     */
    public static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= ERROR_BODY_CHARS ? s : s.substring(0, ERROR_BODY_CHARS);
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
