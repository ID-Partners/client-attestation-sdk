# Security policy

## Reporting a vulnerability

Please report it privately through GitHub: the **Security** tab of this repository, then **Report a
vulnerability**. Don't open a public issue or pull request for it.

Say which port (Go, Java, Python, TypeScript) and which version or commit, and how to reproduce it. A
failing test or a token that should have been rejected is the most useful thing you can send.

You'll get an acknowledgement within five working days. We'll agree a disclosure date with you, and credit
you in the advisory unless you'd rather we didn't.

## Supported versions

The SDK is pre-1.0. Fixes land on the latest minor release only.

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| 0.1.x | No - it predates the one-call API and the fixes listed in the changelog |

## What counts

Anything that lets a credential be accepted when it should be refused, leaks a key, token or attestation,
or lets one workload act as another. That includes the validators accepting a malformed or expired token,
and the one-call client sending a credential somewhere it shouldn't.

The keys in `vectors/inputs.json` and `validation/tokens.json` are public test vectors. They aren't a
vulnerability.
