"""The SDK's loggers. Silent by default: the ``client_attestation_sdk`` logger carries a ``NullHandler``,
so nothing is written until the application configures logging. Event names and attribute keys are the
shared vocabulary in docs/logging.md."""
from __future__ import annotations

import logging
import urllib.parse

from ._redact import is_secret_key, looks_like_secret, redacted

LOGGER_NAME = "client_attestation_sdk"
logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def emit(logger: logging.Logger, level: int, event: str, **attrs) -> None:
    """Log ``event`` with ``attrs`` (``None`` values dropped). The attributes ride on the record as
    ``record.event`` / ``record.attributes`` and are also rendered ``key=value`` into the message. Any
    value under a credential key, or that looks like a credential (a JWT, a Vault token, an
    ``Authorization`` header value), is redacted as a backstop."""
    if not logger.isEnabledFor(level):
        return
    clean = {}
    for key, value in attrs.items():
        if value is None:
            continue
        if is_secret_key(key) or looks_like_secret(value):
            value = redacted(value)
        clean[key] = value
    rendered = " ".join([event] + [f"{key}={_render(value)}" for key, value in clean.items()])
    logger.log(level, "%s", rendered, extra={"event": event, "attributes": clean})


def _render(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return f'"{text}"' if (" " in text or not text) else text


def host(url: str):
    """``host[:port]`` of a URL: never the userinfo, path, query or fragment."""
    try:
        parts = urllib.parse.urlsplit(url)
        name = parts.hostname
        port = parts.port
    except (ValueError, TypeError):
        return None
    if not name:
        return None
    if ":" in name:
        name = f"[{name}]"
    return f"{name}:{port}" if port else name


def path(url: str):
    """The URL's path, without query or fragment."""
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except (ValueError, TypeError):
        return None


def failure_reason(error) -> str:
    """Classify a transport failure for ``http.failed`` / ``jwks.fetch_failed``."""
    status = getattr(error, "status", None)
    message = str(error)
    if status is not None and 300 <= status < 400:
        return "redirect"
    if "larger than" in message:
        return "too_large"
    if "malformed JSON" in message or "not an object" in message:
        return "malformed"
    if status is not None:
        return "status"
    if isinstance(getattr(error, "__cause__", None), TimeoutError) or "timed out" in message.lower():
        return "timeout"
    return "network"
