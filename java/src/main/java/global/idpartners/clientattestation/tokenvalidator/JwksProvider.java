package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.TransportException;
import global.idpartners.clientattestation.internal.HttpTransport;
import global.idpartners.clientattestation.internal.SdkLog;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
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

    /** A verification key, its JWK's {@code kid} and the {@code alg} it declares (each null when absent). */
    record Entry(String kid, Key key, String alg) {

        /** A JWK that declares an alg is only used for that alg. */
        boolean allows(String algorithm) {
            return algorithm == null || this.alg == null || this.alg.equals(algorithm);
        }
    }

    /** The JWK members only a private or symmetric key carries (RFC 7518 section 6). */
    private static final List<String> PRIVATE_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "k");

    private final boolean isStatic;
    private final String jwksUri;
    private final AccessTokenValidator.HttpGet get;
    private final LongSupplier clock;   // monotonic milliseconds, never the validation clock
    private final ValidatorLog log;
    long minRefreshMillis = AccessTokenValidator.DEFAULT_JWKS_MIN_REFRESH.toMillis();
    long maxAgeMillis = AccessTokenValidator.DEFAULT_JWKS_MAX_AGE.toMillis();

    private final ReentrantLock refreshLock = new ReentrantLock();   // one fetch at a time

    // guarded by this
    private List<Entry> keys = List.of();
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

    /**
     * Milliseconds on {@link System#nanoTime()}: the clock the set ages and the refetch cooldown runs on. A
     * wall-clock step, or a fixed validation clock, must not throttle every refetch or keep an old set forever.
     */
    static long monotonicMillis() {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
    }

    /**
     * The usable keys, in document order: kid-less JWKs are distinct keys. Keys that cannot be read, or that may
     * not verify a signature ({@link #verifiesSignatures}), are skipped.
     */
    static List<Entry> parse(Map<String, Object> jwks) {
        List<Entry> out = new ArrayList<>();
        Object list = jwks.get("keys");
        if (!(list instanceof List)) {
            return Collections.unmodifiableList(out);
        }
        for (Object item : (List<?>) list) {
            if (!(item instanceof Map) || !verifiesSignatures((Map<?, ?>) item)) {
                continue;
            }
            try {
                @SuppressWarnings("unchecked")
                JsonWebKey jwk = JsonWebKey.Factory.newJwk((Map<String, Object>) item);
                Key key = jwk instanceof PublicJsonWebKey ? ((PublicJsonWebKey) jwk).getPublicKey() : jwk.getKey();
                if (key == null) {
                    continue;
                }
                out.add(new Entry(jwk.getKeyId(), key, jwk.getAlgorithm()));
            } catch (JoseException | RuntimeException e) {
                // an unreadable key is skipped, the rest still count
            }
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * Whether a JWK may verify a signature: not when its {@code use} is present and not {@code sig}, its
     * {@code key_ops} is present and lacks {@code verify}, or it carries private members.
     */
    static boolean verifiesSignatures(Map<?, ?> jwk) {
        if (jwk.containsKey("use") && !"sig".equals(jwk.get("use"))) {
            return false;
        }
        Object ops = jwk.get("key_ops");
        if (jwk.containsKey("key_ops") && !(ops instanceof List && ((List<?>) ops).contains("verify"))) {
            return false;
        }
        return PRIVATE_MEMBERS.stream().noneMatch(jwk::containsKey);
    }

    /**
     * The verification key for {@code kid} (and {@code alg}), or null. Falls back to the only key when the
     * header has no kid and the set holds exactly one. A key whose JWK declares an alg is only returned for
     * that alg. Never throws: a failed fetch leaves its reason in {@link #lastError()}.
     */
    Key resolve(String kid, String alg) {
        if (!this.isStatic && this.jwksUri != null && !this.jwksUri.isEmpty()) {
            Entry held = lookup(kid, alg);
            if (held == null || stale()) {
                refresh(kid, alg, held != null);
            }
        }
        Entry entry = lookup(kid, alg);
        return entry == null ? null : entry.key();
    }

    /** Why the last fetch failed, or null after a successful one (or before any). */
    synchronized String lastError() {
        return this.lastError;
    }

    /**
     * For a kid, the first key with that kid that may be used for {@code alg} (duplicate kids: document order);
     * without one, the sole key when the set holds exactly one. An empty kid names no key.
     */
    private synchronized Entry lookup(String kid, String alg) {
        if (kid == null) {
            return this.keys.size() == 1 && this.keys.get(0).allows(alg) ? this.keys.get(0) : null;
        }
        if (kid.isEmpty()) {
            return null;
        }
        for (Entry entry : this.keys) {
            if (kid.equals(entry.kid()) && entry.allows(alg)) {
                return entry;
            }
        }
        return null;
    }

    private synchronized boolean stale() {
        return this.loadedAt == null || this.clock.getAsLong() - this.loadedAt >= this.maxAgeMillis;
    }

    private void refresh(String kid, String alg, boolean haveKey) {
        // A caller that already holds a usable (if stale) key never waits for another thread's fetch: it goes on
        // with the key it has. One without a key waits for a fetch in flight, which may bring its key.
        if (haveKey) {
            if (!this.refreshLock.tryLock()) {
                return;
            }
        } else {
            this.refreshLock.lock();
        }
        try {
            if (lookup(kid, alg) != null && !stale()) {
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
            List<Entry> fetched;
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
        } finally {
            this.refreshLock.unlock();
        }
    }

    private List<Entry> fetch() throws FetchFailure {
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
