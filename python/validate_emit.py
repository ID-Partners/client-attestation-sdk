"""Validate every shared token vector and emit this port's verdicts, for the cross-language agreement check."""
import json
import os

from token_validator import AccessTokenValidator, ValidatorConfig

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATION = os.path.normpath(os.path.join(HERE, "..", "validation"))

with open(os.path.join(VALIDATION, "tokens.json")) as fh:
    vectors = json.load(fh)

validator = AccessTokenValidator(ValidatorConfig(
    issuer=vectors["issuer"],
    audiences=[vectors["audience"]],
    jwks=vectors["jwks"],
    required_scopes=vectors["required_scopes"],
    accepted_algorithms=vectors["accepted_algorithms"],
))

results = []
for case in vectors["cases"]:
    result = validator.validate(case["token"])
    results.append({"name": case["name"], "valid": result.valid, "error": result.error})

os.makedirs(os.path.join(VALIDATION, "out"), exist_ok=True)
with open(os.path.join(VALIDATION, "out", "python.json"), "w") as fh:
    json.dump({"language": "python", "results": results}, fh, indent=2)
print("wrote validation/out/python.json")
