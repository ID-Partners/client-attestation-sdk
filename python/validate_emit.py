"""Validate every shared vector (tokens.json, introspection.json, config.json) and emit this port's verdicts, for the
cross-language agreement check."""
import json
import os

from client_attestation_sdk.errors import TransportError
from client_attestation_sdk.token_validator import (AccessTokenValidator, IntrospectionConfig, ProtectedResource,
                                                     ValidatorConfig)

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATION = os.path.normpath(os.path.join(HERE, "..", "validation"))


def load(name):
    with open(os.path.join(VALIDATION, name)) as fh:
        return json.load(fh)


vectors = load("tokens.json")


JWKS_URI = "https://keys.internal.example:8443/jwks"


def config_for(overrides=None, introspection=None, case=None):
    """The shared config, with a case's overrides; an override key that is present wins even when empty. A
    case's own key set replaces the shared one; a case with a fetch error gets a jwks_uri instead."""
    case = case or {}
    fetch = "jwks_fetch_error" in case
    options = {
        "jwks": None if fetch else case.get("jwks", vectors["jwks"]),
        "jwks_uri": JWKS_URI if fetch else None,
        "required_scopes": vectors["required_scopes"],
        "accepted_algorithms": vectors["accepted_algorithms"],
        "introspection": introspection,
    }
    for key in ("accepted_algorithms", "accepted_token_types", "leeway_seconds"):
        if overrides and key in overrides:
            options[key] = overrides[key]
    return ValidatorConfig(issuer=vectors["issuer"], audiences=[vectors["audience"]], **options)


results = []
for case in vectors["cases"]:
    def get(url, case=case):
        raise TransportError(case["jwks_fetch_error"], status=503)

    clock = (lambda now=case["now"]: float(now)) if "now" in case else None
    validator = AccessTokenValidator(config_for(case.get("config"), case=case), http_get=get, clock=clock)
    result = validator.validate(case["token"])
    results.append({"name": case["name"], "valid": result.valid, "error": result.error,
                    "description": result.error_description})

introspection_results = []
for case in load("introspection.json")["cases"]:
    def post(url, body, headers, case=case):
        if case.get("transport_error"):
            raise TransportError("introspection endpoint returned HTTP 503", status=503)
        return case["response"]

    endpoint = None if case.get("no_endpoint") else IntrospectionConfig(
        "https://issuer.example.com/introspect", "rs", "secret")
    validator = AccessTokenValidator(config_for(introspection=endpoint), http_post=post)
    try:
        result = validator.validate_active("opaque-token")
        row = {"name": case["name"], "valid": result.valid, "error": result.error}
    except Exception:
        row = {"name": case["name"], "valid": False, "error": "raises"}
    introspection_results.append(row)

guard = load("introspection.json")["guard"]
guard_results = []
for case in load("introspection.json")["cases"]:
    def post(url, body, headers, case=case):
        if case.get("transport_error"):
            raise TransportError("introspection endpoint returned HTTP 503", status=503)
        return case["response"]

    endpoint = None if case.get("no_endpoint") else IntrospectionConfig(
        "https://issuer.example.com/introspect", "rs", "secret")
    config = ValidatorConfig(issuer=vectors["issuer"], audiences=guard["audiences"], jwks=vectors["jwks"],
                             required_scopes=vectors["required_scopes"], introspection=endpoint)
    resource = ProtectedResource(guard["resource"], [vectors["issuer"]],
                                 AccessTokenValidator(config, http_post=post))
    try:
        decision = resource.authenticate_active("Bearer opaque-token")
        row = {"name": case["name"], "valid": decision.authorized,
               "error": None if decision.authorized else decision.result.error}
    except Exception:
        row = {"name": case["name"], "valid": False, "error": "raises"}
    guard_results.append(row)

config_results = []
for case in load("config.json")["cases"]:
    cfg = case["config"]
    options = {"jwks": None if "jwks_uri" in cfg else vectors["jwks"], "jwks_uri": cfg.get("jwks_uri"),
               "allow_insecure": cfg.get("allow_insecure", False)}
    if "introspection_endpoint" in cfg:
        options["introspection"] = IntrospectionConfig(cfg["introspection_endpoint"], "rs", "secret")
    if "leeway_seconds" in cfg:
        options["leeway_seconds"] = cfg["leeway_seconds"]
    try:
        AccessTokenValidator(ValidatorConfig(issuer=vectors["issuer"], audiences=[vectors["audience"]], **options))
        row = {"name": case["name"], "valid": True, "error": None}
    except ValueError:
        row = {"name": case["name"], "valid": False, "error": "refused"}
    config_results.append(row)

os.makedirs(os.path.join(VALIDATION, "out"), exist_ok=True)
with open(os.path.join(VALIDATION, "out", "python.json"), "w") as fh:
    json.dump({"language": "python", "results": results, "introspection_results": introspection_results,
               "guard_results": guard_results,
               "config_results": config_results}, fh, indent=2)
print("wrote validation/out/python.json")
