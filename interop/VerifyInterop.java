import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationResult;
import com.pingidentity.ps.oidf.common.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.Jwks;
import com.pingidentity.ps.oidf.common.StaticAttesterKeyResolver;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.json.JsonUtil;

/**
 * Cross-language interop gate. Reads the shared vectors/inputs.json (for the attester public key and the
 * expected audience / token endpoint / client_id) and every vectors/out/&lt;lang&gt;.json a port emitted,
 * then runs each through the real AS-side ClientAttestationVerifier in both PoP and DPoP modes. Prints a
 * per-language verdict and exits non-zero if any port is rejected.
 */
public class VerifyInterop {

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path vectors = Path.of(args.length > 0 ? args[0] : "vectors");
        Map<String, Object> inputs = JsonUtil.parseJson(Files.readString(vectors.resolve("inputs.json")));
        Map<String, Object> attester = (Map<String, Object>) inputs.get("attester");
        String attesterIss = (String) attester.get("iss");
        Map<String, Object> attesterJwk = new LinkedHashMap<>((Map<String, Object>) attester.get("jwk"));
        attesterJwk.remove("d"); // register the attester's PUBLIC key only, as a real AS would hold
        JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(attesterJwk);
        // A real AS keys its JWKS by RFC 7638 thumbprint; set it so it matches the kid each port stamps
        // on the attestation header (which also proves every port computes the same thumbprint as jose4j).
        attesterPub.setKeyId(Jwks.thumbprint(attesterPub));
        String audience = (String) inputs.get("audience");
        String tokenEndpoint = (String) inputs.get("token_endpoint");
        String clientId = (String) inputs.get("client_id");

        StaticAttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(attesterIss, List.of(attesterPub)));
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(audience)
                .expectedHtu(tokenEndpoint)
                .build();

        Path outDir = vectors.resolve("out");
        List<Path> files = new ArrayList<>();
        if (Files.isDirectory(outDir)) {
            try (Stream<Path> s = Files.list(outDir)) {
                s.filter(p -> p.toString().endsWith(".json")).sorted().forEach(files::add);
            }
        }
        List<String> missing = new ArrayList<>();
        for (String lang : List.of("go", "python", "typescript")) {
            if (!Files.isRegularFile(outDir.resolve(lang + ".json"))) {
                missing.add(lang);
            }
        }
        if (!missing.isEmpty()) {
            System.out.println("Missing vector output from " + String.join(", ", missing) + " in " + outDir.toAbsolutePath());
            System.exit(2);
        }

        int failures = 0;
        for (Path f : files) {
            Map<String, Object> o = JsonUtil.parseJson(Files.readString(f));
            String lang = String.valueOf(o.getOrDefault("language", f.getFileName().toString()));
            String attestation = (String) o.get("attestation");
            String pop = (String) o.get("pop");
            String dpop = (String) o.get("dpop");

            String popResult = check(() -> {
                ClientAttestationResult r = newVerifier(resolver, config)
                        .verify(attestation, pop, null, "POST", tokenEndpoint, clientId);
                return r.mode() == ClientAttestationResult.Mode.POP_JWT && clientId.equals(r.clientId());
            });
            String dpopResult = check(() -> {
                ClientAttestationResult r = newVerifier(resolver, config)
                        .verify(attestation, null, dpop, "POST", tokenEndpoint, clientId);
                return r.mode() == ClientAttestationResult.Mode.DPOP && clientId.equals(r.clientId());
            });

            if (!popResult.equals("OK") || !dpopResult.equals("OK")) {
                failures++;
            }
            System.out.printf("  %-12s PoP=%s   DPoP=%s%n", lang, popResult, dpopResult);
        }
        System.out.println(failures == 0
                ? "INTEROP OK — every port's credential accepted by the Java AS-side verifier"
                : "INTEROP FAILED — " + failures + " port(s) rejected");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static ClientAttestationVerifier newVerifier(StaticAttesterKeyResolver resolver, ClientAttestationConfig config) {
        return new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
    }

    private interface Check {
        boolean run() throws Exception;
    }

    private static String check(Check c) {
        try {
            return c.run() ? "OK" : "WRONG-MODE";
        } catch (Exception e) {
            return "FAIL(" + e.getMessage() + ")";
        }
    }
}
