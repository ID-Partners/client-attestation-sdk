/**
 * A dependency-free OAuth-protected resource server (MCP-style) built with ProtectedResource.
 *
 * The same shape serves an MCP server or an A2A agent — only the audience (this resource's canonical URI)
 * and the authorization server change. Run: `npx tsx examples/protected-resource-server.ts`
 *
 *   curl -s  localhost:8770/.well-known/oauth-protected-resource            # RFC 9728 metadata
 *   curl -i  localhost:8770/mcp                                             # 401 + WWW-Authenticate
 *   curl -i  -H 'Authorization: Bearer <token>' localhost:8770/mcp          # 200 when valid for this resource
 */
import { createServer } from "node:http";

import { AccessTokenValidator, ProtectedResource } from "../src/validator/index.js";

const RESOURCE = "http://localhost:8770"; // this server's canonical URI (RFC 8707) — the token audience
const ISSUER = "https://issuer.example.com"; // the authorization server clients get a token from

const validator = new AccessTokenValidator({
  issuer: ISSUER,
  audiences: [RESOURCE], // reject tokens minted for a different service (RFC 8707)
  jwksUri: `${ISSUER}/jwks`,
  requiredScopes: ["mcp:call"],
});
const resource = new ProtectedResource(RESOURCE, [ISSUER], validator, ["mcp:call"]);

createServer(async (req, res) => {
  if (req.url === resource.metadataPath()) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(resource.metadata()));
    return;
  }
  const decision = await resource.authenticate(req.headers.authorization);
  if (!decision.authorized) {
    res.writeHead(decision.status, {
      "WWW-Authenticate": decision.wwwAuthenticate ?? "Bearer",
      "Content-Type": "application/json",
    });
    res.end(JSON.stringify({ error: decision.error ?? "unauthorized" }));
    return;
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true, sub: decision.result?.subject, scopes: decision.result?.scopes }));
}).listen(8770, () => console.log("protected resource on", RESOURCE));
