"""A dependency-free OAuth-protected resource server (MCP-style) built with ProtectedResource.

The same shape works for an MCP server or an A2A agent — only the audience (this resource's canonical URI)
and the authorization server change. Run:

    PYTHONPATH=../src python3 protected_resource_server.py

then:

    curl -s  localhost:8770/.well-known/oauth-protected-resource        # RFC 9728 metadata
    curl -i  localhost:8770/mcp                                          # 401 + WWW-Authenticate
    curl -i  -H 'Authorization: Bearer <token>' localhost:8770/mcp       # 200 when valid for this resource
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from token_validator import AccessTokenValidator, ProtectedResource, ValidatorConfig

RESOURCE = "http://localhost:8770"          # this server's canonical URI (RFC 8707) — the token audience
ISSUER = "https://issuer.example.com"       # the authorization server clients get a token from

# The audience MUST be this resource, so a token minted for a different service is rejected (RFC 8707).
validator = AccessTokenValidator(ValidatorConfig(
    issuer=ISSUER, audiences=[RESOURCE], jwks_uri=ISSUER + "/jwks", required_scopes=["mcp:call"]))
resource = ProtectedResource(RESOURCE, [ISSUER], validator, scopes_supported=["mcp:call"])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == resource.metadata_path():
            return self._json(200, resource.metadata())
        decision = resource.authenticate(self.headers.get("Authorization"))
        if not decision.authorized:
            self.send_response(decision.status)
            self.send_header("WWW-Authenticate", decision.www_authenticate)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": decision.error or "unauthorized"}).encode())
            return
        self._json(200, {"ok": True, "sub": decision.result.subject, "scopes": decision.result.scopes})

    def _json(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print("protected resource listening on", RESOURCE)
    HTTPServer(("127.0.0.1", 8770), Handler).serve_forever()
