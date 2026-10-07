"""Deprecated alias for :mod:`client_attestation_sdk.token_validator`. Removed in 0.4.0.

Importing this package warns once and re-exports the new package's public API. Submodule imports
(``from token_validator.jwks import JwksProvider``) resolve to the same module objects.
"""
import sys as _sys
import warnings as _warnings

from client_attestation_sdk import token_validator as _new
from client_attestation_sdk.token_validator import *  # noqa: F401,F403
from client_attestation_sdk.token_validator import (  # noqa: F401
    __all__, __version__, config, discovery, errors, jwks, resource, result, validator,
)

_warnings.warn(
    "the top-level 'token_validator' package is deprecated; import from "
    "'client_attestation_sdk.token_validator' instead. The 'token_validator' alias will be removed in 0.4.0.",
    DeprecationWarning,
    stacklevel=2,
)

for _name in ("config", "discovery", "errors", "jwks", "resource", "result", "validator"):
    _sys.modules[f"{__name__}.{_name}"] = getattr(_new, _name)
del _name
