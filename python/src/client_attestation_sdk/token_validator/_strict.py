"""The strict parsing every port applies to a token before trusting any of it (validation/SEMANTICS.md):
compact serialisation, strict JSON objects, NumericDates and claim types. A failure raises
:class:`Malformed`; its message is generic and never quotes token bytes."""
from __future__ import annotations

import base64
import json
import math
import re

MAX_DEPTH = 64
MAX_SAFE_INTEGER = 2**53 - 1

_SEGMENT = re.compile(r"[A-Za-z0-9_-]*\Z")


class Malformed(ValueError):
    """The input is not well-formed; the token is invalid."""


def b64url_decode(segment):
    if not _SEGMENT.match(segment) or len(segment) % 4 == 1:
        raise Malformed("malformed token")
    data = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii") != segment:
        raise Malformed("malformed token")   # non-zero padding bits: not the canonical encoding
    return data


def split_compact(token):
    """(header object, signing input bytes, payload bytes, signature bytes) of a compact JWS. The payload is
    returned undecoded: it is only parsed once the signature over it verifies."""
    if not isinstance(token, str):
        raise Malformed("malformed token")
    parts = token.split(".")
    if len(parts) != 3:
        raise Malformed("malformed token")
    header_bytes, payload, signature = (b64url_decode(p) for p in parts)
    header = parse_object(header_bytes, "header")
    if "crit" in header:
        # we implement no JWS extension, so RFC 7515 section 4.1.11 says reject any crit
        raise Malformed("header has crit")
    return header, (parts[0] + "." + parts[1]).encode("ascii"), payload, signature


def _reject_constant(_name):
    raise Malformed("not JSON")


def _unique(pairs):
    out = {}
    for name, value in pairs:
        if name in out:
            raise Malformed("duplicate member name")
        out[name] = value
    return out


def _parse_int(digits):
    # Python refuses to make an int of more than 4300 digits; read it as every other port does, as a double
    # (which overflows to infinity), so it is malformed only where a NumericDate is expected
    return int(digits) if len(digits) <= 4000 else float(digits)


def _depth(text):
    """Deepest object/array nesting, counted without recursion (strings skipped)."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def parse_object(data, what="payload"):
    """``data`` (bytes) as a strict RFC 8259 JSON object: UTF-8 without a BOM, no NaN/Infinity, no duplicate
    member names at any depth, at most MAX_DEPTH levels deep."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed(f"{what} is not UTF-8") from None
    if _depth(text) > MAX_DEPTH:
        raise Malformed(f"{what} is nested too deeply")
    try:
        value = json.loads(text, object_pairs_hook=_unique, parse_constant=_reject_constant,
                           parse_int=_parse_int)
    except Malformed as exc:
        raise Malformed(f"{what} is not a strict JSON object ({exc})") from None
    except (ValueError, RecursionError):
        raise Malformed(f"{what} is not JSON") from None
    if not isinstance(value, dict):
        raise Malformed(f"{what} is not a JSON object")
    return value


def numeric_date(claims, name):
    """A NumericDate claim as an int (fractions truncate toward zero), ``None`` when absent or null. Anything
    but a finite JSON number within +/-(2**53 - 1) is malformed."""
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Malformed(f"{name} is not a NumericDate")
    if isinstance(value, float) and not math.isfinite(value):
        raise Malformed(f"{name} is not a NumericDate")
    if abs(value) > MAX_SAFE_INTEGER:
        raise Malformed(f"{name} is out of range")
    return int(value)


def audience(claims):
    """``aud`` as a list: absent or null is empty, a string is one entry, an array must hold only strings."""
    value = claims.get("aud")
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(a, str) for a in value):
        return list(value)
    raise Malformed("aud is not a string or an array of strings")


def _split(text):
    # delimited by U+0020 only, as RFC 6749 section 3.3 says; runs of spaces make no empty scopes
    return [s for s in text.split(" ") if s]


def scopes(claims):
    """Granted scopes: from ``scope`` (a space-delimited string) when present, else ``scp`` (a space-delimited
    string, as Microsoft Entra ID issues it, or an array of strings). Either one present with any other shape
    is malformed."""
    scope = claims.get("scope")
    scp = claims.get("scp")
    if scope is not None and not isinstance(scope, str):
        raise Malformed("scope is not a string")
    if scp is not None and not isinstance(scp, str) and not (
            isinstance(scp, list) and all(isinstance(s, str) for s in scp)):
        raise Malformed("scp is not a string or an array of strings")
    if scope is not None:
        return _split(scope)
    if isinstance(scp, str):
        return _split(scp)
    return list(scp) if scp is not None else []


def subject(claims):
    """``sub``, ``None`` when absent or null; any other non-string is malformed."""
    value = claims.get("sub")
    if value is not None and not isinstance(value, str):
        raise Malformed("sub is not a string")
    return value
