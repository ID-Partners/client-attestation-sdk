/**
 * Client-side SDK for OAuth Attestation-Based Client Authentication, and a resource-server access-token
 * validator.
 *
 * <p>The two exported packages are the API; docs/api.md in the repository says which parts are Stable and
 * which are Experimental. {@code global.idpartners.clientattestation.internal} is not exported: it is
 * plumbing the SDK's packages share, and it may change in any release.
 */
module global.idpartners.clientattestation {
    // SigningKeyPair takes and returns jose4j JWK types, and ClientAttestation.send takes java.net.http types
    requires transitive org.jose4j;
    requires transitive java.net.http;

    exports global.idpartners.clientattestation;
    exports global.idpartners.clientattestation.tokenvalidator;
}
