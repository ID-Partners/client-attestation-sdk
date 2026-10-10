"""OAuth 2.0/2.1 protected-resource conventions on top of :class:`AccessTokenValidator`.

A ``ProtectedResource`` is the resource-server side of any OAuth-protected HTTP service — an MCP server
(OAuth 2.1 resource server per the MCP authorization spec), an A2A agent, or a plain REST API. It adds the
transport conventions the token validator itself doesn't cover:

* RFC 9728 Protected Resource Metadata (``/.well-known/oauth-protected-resource``) advertising the
  authorization server(s) — what an MCP server MUST expose so clients can discover where to get a token;
* RFC 6750 bearer-token extraction and the ``WWW-Authenticate`` challenge on a 401;
* a request guard that binds the token's audience to this resource (RFC 8707) and maps failures to the
  right status (401 vs 403).

Protocol-neutral: nothing here is MCP-only.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from . import errors
from .result import ValidationResult

BEARER = "bearer"
_WELL_KNOWN = "/.well-known/oauth-protected-resource"


def bearer_token(authorization_header):
    """Extract the token from an ``Authorization: Bearer <token>`` header value, or ``None`` if the header
    is absent, blank, or not a Bearer credential."""
    if not authorization_header:
        return None
    parts = authorization_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == BEARER and parts[1].strip():
        return parts[1].strip()
    return None


class AuthDecision:
    """The outcome of guarding a request. Truthy when authorized. On failure it carries the HTTP ``status``
    (401 or 403) and the ``www_authenticate`` header value to return."""

    def __init__(self, authorized, *, result=None, status=200, www_authenticate=None,
                 error=None, error_description=None):
        self.authorized = authorized
        self.result = result
        self.status = status
        self.www_authenticate = www_authenticate
        self.error = error
        self.error_description = error_description

    def __bool__(self):
        return self.authorized


# validator error code -> (HTTP status, RFC 6750 error). insufficient_scope is the only 403.
def _http_error(error):
    if error == errors.INSUFFICIENT_SCOPE:
        return 403, "insufficient_scope"
    return 401, "invalid_token"


class ProtectedResource:
    """An OAuth-protected resource server (e.g. an MCP server or A2A agent).

    ``validator`` must be an :class:`AccessTokenValidator` that accepts ``resource`` as an audience — that
    binds incoming tokens to this resource (RFC 8707), which MCP servers MUST enforce. The constructor
    refuses one that doesn't.
    """

    def __init__(self, resource, authorization_servers, validator, scopes_supported=None):
        if resource not in validator.config.audiences:
            raise ValueError(f"the validator does not accept this resource ({resource}) as an audience")
        self.resource = resource
        self.authorization_servers = list(authorization_servers or [])
        self.validator = validator
        self.scopes_supported = list(scopes_supported or [])

    def metadata(self):
        """RFC 9728 protected-resource metadata. Serve this JSON at :meth:`metadata_path`."""
        md = {
            "resource": self.resource,
            "authorization_servers": self.authorization_servers,
            "bearer_methods_supported": ["header"],
        }
        if self.scopes_supported:
            md["scopes_supported"] = self.scopes_supported
        return md

    def metadata_path(self):
        """The path to serve the metadata at, per RFC 9728 §3: ``/.well-known/oauth-protected-resource``
        with the resource's path (if any) appended."""
        path = urlsplit(self.resource).path
        return _WELL_KNOWN + path if path and path != "/" else _WELL_KNOWN

    def metadata_url(self):
        """The absolute URL of the metadata document."""
        parts = urlsplit(self.resource)
        return urlunsplit((parts.scheme, parts.netloc, self.metadata_path(), "", ""))

    def challenge(self, error=None, error_description=None):
        """Build the ``WWW-Authenticate: Bearer …`` header value (RFC 6750 + RFC 9728 §5.1), always pointing
        at this resource's metadata."""
        params = []
        if error:
            params.append(f'error="{_quote(error)}"')
            if error_description:
                params.append(f'error_description="{_quote(error_description)}"')
        params.append(f'resource_metadata="{_quote(self.metadata_url())}"')
        return "Bearer " + ", ".join(params)

    def authenticate(self, authorization_header, required_scopes=None):
        """Guard a request: extract the bearer token, validate it (audience must be this resource, plus any
        ``required_scopes``), and return an :class:`AuthDecision`. Missing/invalid/expired/wrong-audience →
        401; insufficient scope → 403."""
        token = bearer_token(authorization_header)
        if token is None:
            return AuthDecision(False, status=401, www_authenticate=self.challenge(),
                                error_description="authentication required")
        result = self.validator.validate(token, required_scopes)
        if result.valid and self.resource not in result.audience:
            result = ValidationResult._failure(errors.INVALID_AUDIENCE, "token audience is not this resource")
        if result.valid and result.claims.get("cnf") is not None:
            result = ValidationResult._failure(errors.INVALID_TOKEN, "sender-constrained token requires proof verification")
        if result.valid:
            return AuthDecision(True, result=result)
        status, oauth_error = _http_error(result.error)
        return AuthDecision(False, result=result, status=status, error=oauth_error,
                            error_description=result.error_description,
                            www_authenticate=self.challenge(oauth_error, result.error_description))


_CONTROL_CHARS = {c: None for c in list(range(0x20)) + [0x7F]}


def _quote(value):
    """Make ``value`` safe inside a quoted-string: drop CR, LF and every other control character
    (0x00-0x1F, 0x7F) so nothing can split or inject header lines, then escape backslash and double quote."""
    return str(value).translate(_CONTROL_CHARS).replace("\\", "\\\\").replace('"', '\\"')
