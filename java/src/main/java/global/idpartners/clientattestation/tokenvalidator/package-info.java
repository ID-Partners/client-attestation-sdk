/**
 * Resource-server access-token validation: JWT signature, {@code typ}, issuer, expiry, audience and scope
 * checks in a fixed, cross-language order, plus optional RFC 7662 introspection, authorization-server
 * metadata discovery and the RFC 9728 / RFC 6750 protected-resource helper.
 *
 * <p>The validation order and the stable error codes in {@link
 * global.idpartners.clientattestation.tokenvalidator.ErrorCodes} are a contract shared with the Python,
 * TypeScript and Go ports, so every port reports the same verdict for the same token. The shared vectors in
 * {@code validation/tokens.json} pin it.
 *
 * <pre>{@code
 * AccessTokenValidator validator = new AccessTokenValidator(ValidatorConfig.builder()
 *         .issuer("https://issuer.example.com")
 *         .audiences("https://api.example.com")
 *         .jwksUri("https://issuer.example.com/jwks")
 *         .requiredScopes("read")
 *         .build());
 *
 * ValidationResult result = validator.validate(accessToken);
 * if (result.valid()) {
 *     handle(result.subject(), result.scopes());
 * }
 * }</pre>
 */
package global.idpartners.clientattestation.tokenvalidator;
