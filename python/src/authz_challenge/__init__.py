"""Deprecated alias for :mod:`client_attestation_sdk.authz_challenge`. Removed in 0.4.0.

Importing this package warns once and re-exports the new package's public API. Submodule imports
(``from authz_challenge.resolver import new_handle``) resolve to the same module objects.
"""
import sys as _sys
import warnings as _warnings

from client_attestation_sdk import authz_challenge as _new
from client_attestation_sdk.authz_challenge import *  # noqa: F401,F403
from client_attestation_sdk.authz_challenge import __all__, __version__, challenge, ciba, resolver  # noqa: F401

_warnings.warn(
    "the top-level 'authz_challenge' package is deprecated; import from "
    "'client_attestation_sdk.authz_challenge' instead. The 'authz_challenge' alias will be removed in 0.4.0.",
    DeprecationWarning,
    stacklevel=2,
)

for _name in ("challenge", "ciba", "resolver"):
    _sys.modules[f"{__name__}.{_name}"] = getattr(_new, _name)
del _name
