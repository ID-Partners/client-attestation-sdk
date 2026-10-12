package global.idpartners.clientattestation.tokenvalidator;

import static global.idpartners.clientattestation.tokenvalidator.Fixtures.AUDIENCE;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.ISSUER;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.claims;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.jwksJson;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.newKey;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.sign;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.junit.jupiter.api.Test;

/** JWKS resolution and the jwks_uri refresh policy: cooldown, single flight, max age, size cap, fail-safe. */
class JwksProviderTest {

    private static final String URI = "https://as.test/jwks";
    private final AtomicLong clock = new AtomicLong(1_000_000_000L);

    private JwksProvider uriProvider(AccessTokenValidator.HttpGet get) {
        return new JwksProvider(null, URI, get, this.clock::get, new ValidatorLog(null));
    }

    // ── static sets ─────────────────────────────────────────────────────────────────────────────────

    @Test
    void staticSetFallsBackToTheOnlyKeyWithoutKid() {
        EllipticCurveJsonWebKey k = newKey("only");
        JwksProvider p = new JwksProvider(Fixtures.jwks(k), null, null, this.clock::get, new ValidatorLog(null));
        assertNotNull(p.resolve(null, "ES256"));
        assertNotNull(p.resolve("only", null));
        assertNull(p.resolve("unknown", "ES256"));
        assertNull(p.lastError());
    }

    @Test
    void staticSetWithSeveralKeysNeedsAKid() {
        JwksProvider p = new JwksProvider(Fixtures.jwks(newKey("a"), newKey("b")), null, null, this.clock::get,
                new ValidatorLog(null));
        assertNull(p.resolve(null, "ES256"));
        assertNotNull(p.resolve("b", "ES256"));
    }

    @Test
    void documentWithoutKeysAndUnreadableKeysAreTolerated() throws Exception {
        assertTrue(JwksProvider.parse(Map.of()).isEmpty());
        assertTrue(JwksProvider.parse(Map.of("keys", "nope")).isEmpty());
        RsaJsonWebKey rsa = RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("rsa");
        Map<String, Object> octet = new LinkedHashMap<>(Map.of("kty", "oct", "k", "c2VjcmV0LXNlY3JldC1zZWNyZXQ", "kid", "hs"));
        List<Object> keys = new ArrayList<>();
        keys.add("not a key");
        keys.add(Map.of("kty", "EC", "crv", "P-256", "kid", "broken"));
        keys.add(Map.of("kty", "nope", "kid", "unknown-type"));
        keys.add(Fixtures.publicJwk(newKey("ec")));
        keys.add(Fixtures.publicJwk(rsa));
        keys.add(octet);
        List<String> kids = new ArrayList<>();
        JwksProvider.parse(Map.of("keys", keys)).forEach(entry -> kids.add(entry.kid()));
        // the symmetric key is skipped too: "k" is a private member
        assertEquals(List.of("ec", "rsa"), kids);
    }

    @Test
    void firstKeyWithTheSameKidWins() {
        EllipticCurveJsonWebKey first = newKey("dup");
        EllipticCurveJsonWebKey second = newKey("dup");
        AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER).audiences(AUDIENCE)
                .jwks(Fixtures.jwks(first, second)).build());
        assertTrue(v.validate(sign(first, claims())).valid());
        assertEquals(ErrorCodes.INVALID_SIGNATURE, v.validate(sign(second, claims())).error());
    }

    // ── jwks_uri ────────────────────────────────────────────────────────────────────────────────────

    @Test
    void jwksUriFetchedOnDemandOnce() {
        EllipticCurveJsonWebKey key = newKey("k1");
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<String> fetched = new AtomicReference<>();
        AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwksUri(URI).build()).httpGet(url -> {
                    calls.incrementAndGet();
                    fetched.set(url);
                    return jwksJson(key);
                }).build();
        assertTrue(v.validate(sign(key, claims())).valid());
        assertTrue(v.validate(sign(key, claims())).valid());
        assertEquals(1, calls.get());
        assertEquals(URI, fetched.get());
    }

    @Test
    void unknownKidsCannotForceAFetchPerRequest() {
        AtomicInteger calls = new AtomicInteger();
        String set = jwksJson(newKey("real"));
        JwksProvider p = uriProvider(url -> {
            calls.incrementAndGet();
            return set;
        });
        assertNotNull(p.resolve("real", null));
        for (int i = 0; i < 100; i++) {
            assertNull(p.resolve("made-up", null));
        }
        assertEquals(1, calls.get(), "fetched inside the cooldown");
        this.clock.addAndGet(AccessTokenValidator.DEFAULT_JWKS_MIN_REFRESH.toMillis());
        p.resolve("made-up", null);
        assertEquals(2, calls.get(), "fetched after the cooldown");
    }

    @Test
    void concurrentMissesShareOneFetch() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        String set = jwksJson(newKey("k"));
        JwksProvider p = uriProvider(url -> {
            calls.incrementAndGet();
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return set;
        });
        ExecutorService pool = Executors.newFixedThreadPool(10);
        try {
            List<Future<Object>> results = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                results.add(pool.submit(() -> p.resolve("k", null)));
            }
            Thread.sleep(100);
            release.countDown();
            int found = 0;
            for (Future<Object> f : results) {
                found += f.get(5, TimeUnit.SECONDS) != null ? 1 : 0;
            }
            assertEquals(1, calls.get());
            assertEquals(10, found);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void oldKeysAreRefreshedAndKeptWhenTheRefreshFails() {
        String oldSet = jwksJson(newKey("old"));
        String newSet = jwksJson(newKey("new"));
        AtomicReference<String> served = new AtomicReference<>(oldSet);
        AtomicReference<RuntimeException> fail = new AtomicReference<>();
        JwksProvider p = uriProvider(url -> {
            if (fail.get() != null) {
                throw fail.get();
            }
            return served.get();
        });
        p.maxAgeMillis = 10 * 60_000L;
        assertNotNull(p.resolve("old", null));
        served.set(newSet);
        this.clock.addAndGet(10 * 60_000L);
        assertNotNull(p.resolve("new", null), "the rotated key after max age");
        fail.set(new IllegalStateException("issuer down"));
        this.clock.addAndGet(10 * 60_000L);
        assertNotNull(p.resolve("new", null), "a failed refresh keeps the keys already held");
        this.clock.addAndGet(60_000L);
        assertNull(p.resolve("unknown", null));
        assertTrue(p.lastError().contains("issuer down"), p.lastError());
    }

    @Test
    void fetchFailureIsKeyNotFoundNotAnException() {
        EllipticCurveJsonWebKey key = newKey("k1");
        AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwksUri(URI).build()).httpGet(url -> {
                    throw new IllegalStateException("boom");
                }).build();
        ValidationResult r = v.validate(sign(key, claims()));
        assertEquals(ErrorCodes.KEY_NOT_FOUND, r.error());
        // the description reaches WWW-Authenticate: the fetch failure's detail stays in the log
        assertEquals("signing keys unavailable", r.errorDescription());
    }

    @Test
    void aCallerHoldingAStaleKeyNeverWaitsForAFetch() throws Exception {
        String set = jwksJson(newKey("k"));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Boolean> slow = new AtomicReference<>(false);
        JwksProvider p = uriProvider(url -> {
            if (slow.get()) {
                started.countDown();
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return set;
        });
        assertNotNull(p.resolve("k", "ES256"));
        slow.set(true);
        this.clock.addAndGet(AccessTokenValidator.DEFAULT_JWKS_MAX_AGE.toMillis());   // stale: the next caller refetches
        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            Future<Object> fetcher = pool.submit(() -> p.resolve("k", "ES256"));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            Future<Object> holder = pool.submit(() -> p.resolve("k", "ES256"));
            Object stale;
            try {
                stale = holder.get(2, TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException e) {
                stale = null;
            }
            // a caller without the key waits for the fetch in flight, which may bring it
            Future<Object> misser = pool.submit(() -> p.resolve("other", "ES256"));
            Thread.sleep(200);
            boolean waited = !misser.isDone();
            release.countDown();
            assertNotNull(fetcher.get(5, TimeUnit.SECONDS));
            assertNotNull(stale, "a caller with a usable stale key waited for another caller's fetch");
            assertTrue(waited);
            assertNull(misser.get(5, TimeUnit.SECONDS));
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void theValidationClockDoesNotAgeTheJwksCache() {
        EllipticCurveJsonWebKey key = newKey("k");
        AtomicInteger calls = new AtomicInteger();
        AtomicLong validationClock = new AtomicLong(System.currentTimeMillis());
        AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwksUri(URI).build()).clock(validationClock::get).httpGet(url -> {
                    calls.incrementAndGet();
                    return jwksJson(key);
                }).build();
        String token = sign(key, claims("exp", Fixtures.now() + 3 * 3600));
        assertTrue(v.validate(token).valid());
        // validating as of a later instant is not an hour passing for the key set
        validationClock.addAndGet(2 * AccessTokenValidator.DEFAULT_JWKS_MAX_AGE.toMillis());
        assertTrue(v.validate(token).valid());
        assertEquals(1, calls.get(), "a validation clock moved forward refetched the JWKS");
    }

    @Test
    void aFixedValidationClockStillLetsTheJwksCacheRefetch() {
        EllipticCurveJsonWebKey a = newKey("a");
        EllipticCurveJsonWebKey b = newKey("b");
        AtomicReference<String> served = new AtomicReference<>(jwksJson(a));
        AtomicInteger calls = new AtomicInteger();
        long fixed = System.currentTimeMillis();
        AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwksUri(URI).build()).clock(() -> fixed).jwksClock(this.clock::get)
                .httpGet(url -> {
                    calls.incrementAndGet();
                    return served.get();
                }).build();
        assertTrue(v.validate(sign(a, claims())).valid());
        // the issuer rotates to b; once the cooldown has passed, b's kid is fetched
        served.set(jwksJson(b));
        this.clock.addAndGet(AccessTokenValidator.DEFAULT_JWKS_MIN_REFRESH.toMillis());
        assertTrue(v.validate(sign(b, claims())).valid(), "the JWKS was never refetched under a fixed clock");
        assertEquals(2, calls.get());
        // and the set still grows old: a key the issuer removed stops verifying after max age
        served.set(jwksJson(a));
        this.clock.addAndGet(AccessTokenValidator.DEFAULT_JWKS_MAX_AGE.toMillis());
        assertEquals(ErrorCodes.KEY_NOT_FOUND, v.validate(sign(b, claims())).error(),
                "a removed key was trusted past max age");
        assertEquals(3, calls.get());
    }

    @Test
    void unparseableOrEmptyDocumentIsKeyNotFound() {
        EllipticCurveJsonWebKey key = newKey("k1");
        for (String body : new String[] {"not json", "[1]", null}) {
            AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(ISSUER)
                    .audiences(AUDIENCE).jwksUri(URI).build()).httpGet(url -> body).build();
            ValidationResult r = v.validate(sign(key, claims()));
            assertEquals(ErrorCodes.KEY_NOT_FOUND, r.error(), String.valueOf(body));
        }
    }

    @Test
    void refreshThatStillLacksTheKid() {
        EllipticCurveJsonWebKey key = newKey("k1");
        AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwksUri(URI).build()).httpGet(url -> jwksJson(newKey("other"))).build();
        ValidationResult r = v.validate(sign(key, claims()));
        assertEquals(ErrorCodes.KEY_NOT_FOUND, r.error());
        assertEquals("no signing key for this kid", r.errorDescription());
    }

    @Test
    void oversizedJwksIsRefused() {
        String big = "{\"keys\":[],\"padding\":\"" + "x".repeat((int) AccessTokenValidator.MAX_JWKS_BYTES) + "\"}";
        JwksProvider p = uriProvider(url -> big);
        assertNull(p.resolve("any", null));
        assertTrue(p.lastError().contains("larger than"), p.lastError());
    }

    // ── default transport ───────────────────────────────────────────────────────────────────────────

    @Test
    void defaultTransportFetchesOverHttp() throws Exception {
        EllipticCurveJsonWebKey key = newKey("k1");
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/jwks", 200, jwksJson(key));
            AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                    .audiences(AUDIENCE).jwksUri(stub.url("/jwks")).build());
            assertTrue(v.validate(sign(key, claims())).valid());
            assertEquals(1, stub.hits("/jwks"));
            assertEquals("application/json", stub.headers.get("/jwks").getFirst("Accept"));
        }
    }

    @Test
    void defaultTransportRefusesErrorsRedirectsBigBodiesAndDeadEndpoints() throws Exception {
        EllipticCurveJsonWebKey key = newKey("k1");
        String dead;
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/500", 500, "{}");
            stub.respond("/target", 200, jwksJson(key));
            stub.redirect("/redirect", stub.url("/target"));
            stub.respond("/big", 200, "x".repeat((int) AccessTokenValidator.MAX_JWKS_BYTES + 1));
            for (String path : new String[] {"/500", "/redirect", "/big"}) {
                AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                        .audiences(AUDIENCE).jwksUri(stub.url(path)).build());
                assertEquals(ErrorCodes.KEY_NOT_FOUND, v.validate(sign(key, claims())).error(), path);
            }
            assertEquals(0, stub.hits("/target"), "a redirect is never followed");
            dead = stub.url("/jwks");
        }
        AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwksUri(dead).build());
        assertEquals(ErrorCodes.KEY_NOT_FOUND, v.validate(sign(key, claims())).error());
    }
}
