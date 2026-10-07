"""The top-level token_validator and authz_challenge packages are deprecated aliases (removed in 0.4.0).
They must warn, and must hand back the very same objects as the client_attestation_sdk subpackages."""
import importlib
import sys

import pytest

import client_attestation_sdk.authz_challenge as new_ac
import client_attestation_sdk.token_validator as new_tv

SHIMS = [
    ("token_validator", new_tv, ("config", "discovery", "errors", "jwks", "resource", "result", "validator")),
    ("authz_challenge", new_ac, ("challenge", "ciba", "resolver")),
]


def _fresh_import(name):
    for key in [k for k in sys.modules if k == name or k.startswith(name + ".")]:
        del sys.modules[key]
    with pytest.warns(DeprecationWarning, match=rf"client_attestation_sdk\.{name}.*0\.4\.0"):
        return importlib.import_module(name)


@pytest.mark.parametrize("name,new,submodules", SHIMS, ids=[s[0] for s in SHIMS])
def test_shim_warns_and_reexports_public_api(name, new, submodules):
    old = _fresh_import(name)
    assert old.__all__ == new.__all__
    assert old.__version__ == new.__version__
    for attr in new.__all__:
        assert getattr(old, attr) is getattr(new, attr), attr


@pytest.mark.parametrize("name,new,submodules", SHIMS, ids=[s[0] for s in SHIMS])
def test_shim_submodule_imports_are_the_new_modules(name, new, submodules):
    _fresh_import(name)
    for sub in submodules:
        assert importlib.import_module(f"{name}.{sub}") is getattr(new, sub)


def test_shim_submodule_from_imports():
    _fresh_import("token_validator")
    _fresh_import("authz_challenge")
    from token_validator.jwks import JwksProvider
    from token_validator.resource import _quote
    from authz_challenge.resolver import new_handle
    from authz_challenge import ciba as ciba_mod

    from client_attestation_sdk.authz_challenge import ciba, resolver
    from client_attestation_sdk.token_validator import jwks, resource

    assert JwksProvider is jwks.JwksProvider
    assert _quote is resource._quote
    assert new_handle is resolver.new_handle
    assert ciba_mod is ciba
