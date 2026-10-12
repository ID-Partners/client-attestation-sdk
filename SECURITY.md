# Security policy

## Reporting a vulnerability

Please report it privately through GitHub: the **Security** tab of this repository, then **Report a
vulnerability**. Don't open a public issue or pull request for it.

Say which port (Go, Java, Python, TypeScript) and which version or commit, and how to reproduce it. A
failing test or a token that should have been rejected is the most useful thing you can send.

You'll get an acknowledgement within five working days. We'll agree a disclosure date with you, and credit
you in the advisory unless you'd rather we didn't.

## Supported versions

Security fixes land on the latest 1.x minor release, as a patch release.

| Version | Supported |
|---|---|
| 1.x | Yes |
| 0.x | No - pre-1.0 releases get no fixes. Upgrade to 1.x; the changelog lists every break |

## What counts

Anything that lets a credential be accepted when it should be refused, leaks a key, token or attestation,
or lets one workload act as another. That includes the validators accepting a malformed or expired token,
and the one-call client sending a credential somewhere it shouldn't.

The keys in `vectors/inputs.json` and `validation/tokens.json` are public test vectors, including the
private JWKs some `validation/tokens.json` cases put in a JWKS on purpose. They aren't a vulnerability.
