package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.TransportException;
import global.idpartners.clientattestation.internal.HttpTransport;
import global.idpartners.clientattestation.internal.SdkLog;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

/**
 * Resolves issuer signing keys from a static JWKS or a {@code jwks_uri} (fetched and cached, refreshed on an
 * unknown {@code kid} and when the cached set grows old).
 *
 * <p>A {@code jwks_uri} provider never fetches more than once per {@code minRefreshMillis}, however many
 * unknown {@code kid} values it is shown, and concurrent misses share one fetch. Without that, a stream of
 * tokens with made-up {@code kid} values turns every request into a request to the issuer.
 */
final class JwksProvider {

    /** A verification key and the {@code alg} its JWK declares (null when it declares none). */
    record Entry(Key key, String alg) {
    }

    private final boolean isStatic;
    private final String jwksUri;
    private final AccessTokenValidator.HttpGet get;
    private final LongSupplier clock;
    private final ValidatorLog log;
    long minRefreshMillis = AccessTokenValidator.DEFAULT_JWKS_MIN_REFRESH.toMillis();
    long maxAgeMillis = AccessTokenValidator.DEFAULT_JWKS_MAX_AGE.toMillis();

    private final Object refreshLock = new Object();   // one fetch at a time

    // guarded by this
    private Map<String, Entry> keys = Map.of();
    private Long loadedAt;
    private Long lastAttempt;
    private String lastError;

    JwksProvider(Map<String, Object> jwks, String jwksUri, AccessTokenValidator.HttpGet get, LongSupplier clock,
                 ValidatorLog log) {
        this.isStatic = jwks != null;
        this.jwksUri = jwksUri;
        this.get = get;
        this.clock = clock;
        this.log = log;
        if (jwks != null) {
            this.keys = parse(jwks);
        }
    }

    /** kid -&gt; entry. Keys that cannot be read are skipped; a later key with the same kid wins. */
    static Map<String, Entry> parse(Map<String, Object> jwks) {
        Map<String, Entry> out = new LinkedHashMap<>();
        Object list = jwks.get("keys");
        if (!(list instanceof List)) {
            return Collections.unmodifiableMap(out);
        }
        for (Object item : (List<?>) list) {
            if (!(item instanceof Map)) {
                continue;
            }
            try {
                @SuppressWarnings("unchecked")
                JsonWebKey jwk = JsonWebKey.Factory.newJwk((Map<String, Object>) item);
                Key key = jwk instanceof PublicJsonWebKey ? ((PublicJsonWebKey) jwk).getPublicKey() : jwk.getKey();
                if (key == null) {
                    continue;
                }
                out.put(jwk.getKeyId(), new Entry(key, jwk.getAlgorithm()));
            } catch (JoseException | RuntimeException e) {
                // an unreadable key is skipped, the rest still count
            }
        }
        return Collections.unmodifiableMap(out);
    }

    /**
     * The verification key for {@code kid} (and {@code alg}), or null. Falls back to the only key when the
     * header has no kid and the set holds exactly one. A key whose JWK declares an alg is only returned for
     * that alg. Never throws: a failed fetch leaves its reason in {@link #lastError()}.
     */
    Key resolve(String kid, String alg) {
        if (!this.isStatic && this.jwksUri != null && !this.jwksUri.isEmpty()
                && (lookup(kid) == null || stale())) {
            refresh(kid);
        }
        Entry entry = lookup(kid);
        if (entry == null) {
            return null;
        }
        if (alg != null && entry.alg() != null && !entry.alg().equals(alg)) {
            return null;
        }
        return entry.key();
    }

    /** Why the last fetch failed, or null after a successful one (or before any). */
    synchronized String lastError() {
        return this.lastError;
    }

    private synchronized Entry lookup(String kid) {
        if (kid != null) {
            return this.keys.get(kid);
        }
        return this.keys.size() == 1 ? this.keys.values().iterator().next() : null;
    }

    private synchronized boolean stale() {
        return this.loadedAt == null || this.clock.getAsLong() - this.loadedAt >= this.maxAgeMillis;
    }

    private void refresh(String kid) {
        synchronized (this.refreshLock) {
            if (lookup(kid) != null && !stale()) {
                return;   // another caller refreshed while this one waited
            }
            synchronized (this) {
                long now = this.clock.getAsLong();
                if (this.lastAttempt != null && now - this.lastAttempt < this.minRefreshMillis) {
                    this.log.debug("jwks.refetch_throttled", "host", SdkLog.host(this.jwksUri));
                    return;
                }
                this.lastAttempt = now;
            }
            Map<String, Entry> fetched;
            try {
                fetched = fetch();
            } catch (FetchFailure e) {
                this.log.warn("jwks.fetch_failed", "host", SdkLog.host(this.jwksUri), "reason", e.reason,
                        "status", e.status);
                synchronized (this) {
                    this.lastError = "JWKS fetch failed: " + e.getMessage();   // keep the keys already held
                }
                return;
            }
            synchronized (this) {
                this.keys = fetched;
                this.loadedAt = this.clock.getAsLong();
                this.lastError = null;
            }
            this.log.debug("jwks.fetched", "host", SdkLog.host(this.jwksUri), "keys", fetched.size());
        }
    }

    private Map<String, Entry> fetch() throws FetchFailure {
        String body;
        try {
            body = this.get.get(this.jwksUri);
        } catch (RuntimeException e) {
            Integer status = e instanceof TransportException && ((TransportException) e).status() > 0
                    ? ((TransportException) e).status() : null;
            throw new FetchFailure(String.valueOf(e.getMessage()), HttpTransport.failureReason(e), status, e);
        }
        if (body == null) {
            throw new FetchFailure("empty response", "malformed", null, null);
        }
        if (body.getBytes(StandardCharsets.UTF_8).length > AccessTokenValidator.MAX_JWKS_BYTES) {
            throw new FetchFailure("JWKS is larger than " + AccessTokenValidator.MAX_JWKS_BYTES + " bytes",
                    "too_large", null, null);
        }
        try {
            return parse(JsonUtil.parseJson(body));
        } catch (JoseException | RuntimeException e) {
            throw new FetchFailure("JWKS is not a JSON object", "malformed", null, e);
        }
    }

    /** A failed fetch, classified for {@code jwks.fetch_failed}. */
    private static final class FetchFailure extends Exception {
        private static final long serialVersionUID = 1L;
        private final transient String reason;
        private final transient Integer status;

        FetchFailure(String message, String reason, Integer status, Throwable cause) {
            super(message, cause);
            this.reason = reason;
            this.status = status;
        }
    }
}
