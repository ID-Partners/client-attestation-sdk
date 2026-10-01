"""The SDK's exception hierarchy."""
from __future__ import annotations

from typing import Optional


class ClientAttestationError(RuntimeError):
    """A step in the flow failed. `status` and `body` are set for HTTP failures."""

    def __init__(self, message: str, *, status: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.body = body


class TransportError(ClientAttestationError):
    """An outbound HTTP call failed: the network or TLS failed, the call timed out, the server answered
    with a redirect (never followed) or a non-2xx status, the body was over the size cap, or the body was
    not the JSON the caller expected. `status` is the HTTP status when the server answered; `None` when it
    never did."""
