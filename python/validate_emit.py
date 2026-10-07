"""Validate every shared vector (tokens.json, introspection.json) and emit this port's verdicts, for the
cross-language agreement check."""
import json
import os

from client_attestation_sdk.errors import TransportError
from client_attestation_sdk.token_validator import AccessTokenValidator, IntrospectionConfig, ValidatorConfig

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATION = os.path.normpath(os.path.join(HERE, "..", "validation"))


def load(name):
    with open(os.path.join(VALIDATION, name)) as fh:
        return json.load(fh)


vectors = load("tokens.json")


def config_for(overrides=None, introspection=None):
    """The shared config, with a case's overrides; an override key that is present wins even when empty."""
    options = {
        "jwks": vectors["jwks"],
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
    clock = (lambda now=case["now"]: float(now)) if "now" in case else None
    validator = AccessTokenValidator(config_for(case.get("config")), clock=clock)
    result = validator.validate(case["token"])
    results.append({"name": case["name"], "valid": result.valid, "error": result.error})

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

os.makedirs(os.path.join(VALIDATION, "out"), exist_ok=True)
with open(os.path.join(VALIDATION, "out", "python.json"), "w") as fh:
    json.dump({"language": "python", "results": results, "introspection_results": introspection_results},
              fh, indent=2)
print("wrote validation/out/python.json")
