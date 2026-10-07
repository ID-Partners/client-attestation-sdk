# Contributing

## The rule that matters

The four ports have to agree. A change in behaviour lands in every port that has the feature, in the same
pull request, and if the behaviour is observable it gets a case in `vectors/` or `validation/` so the
agreement is checked rather than assumed. A port that can't follow yet is marked in the feature matrix as
missing the feature, not quietly left behind.

## Running everything

You need Go 1.25+, Python 3.11+, Node 20+, a JDK 17+ and Maven.

```bash
(cd go && go vet ./... && go test -race -cover ./...)
(cd python && pip install -e '.[test]' && pytest --cov)
(cd typescript && npm ci && npx tsc --noEmit && npx vitest run --coverage && npm run test:edge)
(cd java && ./mvnw verify)
./verify-validation.sh      # the four validators return the same verdict on every case
./verify-interop.sh         # every port's credential passes the Java AS-side verifier
python3 scripts/api_surface.py --check   # each port's public API matches docs/api-surface/
```

CI runs all of it except `verify-interop.sh`, which needs the AS-side verifier (`client-attestation`
0.1.0) installed in `~/.m2`. That isn't public yet, so run it yourself before you ask for a release, and
use `mvn verify -Pinterop` to include the Java round-trip tests.

Each port has a coverage floor (Go in `ci.yml`, Python in `pyproject.toml`, TypeScript in
`vitest.config.ts`, Java in `pom.xml`). They sit at what was measured when they were set. Raise one when
you add tests; don't lower one to get a change through.

## Changing the public API

Each port's public API is snapshotted in `docs/api-surface/<port>.txt`, generated from the real build by
`scripts/api_surface.py`, and each port's CI job fails if its build no longer matches.
[`docs/api.md`](docs/api.md) says what the API is and which tier (Stable, Experimental, Internal) each
part is in.

An intended API change updates the snapshot in the same pull request: run
`python3 scripts/api_surface.py <port>` (for Python, with an interpreter that has the package's
dependencies, or `--python path/to/python`) and commit the result. It also adds a line under
`[Unreleased]` in `CHANGELOG.md` saying what changed and in which tier. Stable API follows semver: to
remove or rename a Stable name, deprecate it in a minor release (a "Deprecated" entry naming the major
that removes it) and remove it in the next major. Experimental API can change in a minor release. If a
change moves something between tiers, update `docs/api.md` and the item's doc comment too.

A snapshot diff you didn't expect means the change touched the API by accident: fix the code, not the
snapshot.

## Pull requests

This repo is published from the maintainers' source repo, one commit per release. Pull requests are
welcome and are reviewed here as usual, but an accepted one is applied upstream rather than merged, and
comes back in the next release. The pull request is closed with a link to that release.

- Branch from `main`. CI needs the `ci-ok` check to pass.
- Add a line under `[Unreleased]` in `CHANGELOG.md` for anything a user would notice.
- Security problems go through the private route in `SECURITY.md`, not a pull request.

## Releasing

1. `python3 scripts/version.py set X.Y.Z` (writes `VERSION` and every copy; CI checks they agree).
2. Move `[Unreleased]` in `CHANGELOG.md` to that version and date it.
3. Run `./verify-interop.sh`.
4. In the source repo, merge, tag `vX.Y.Z` on `main` and run the publish workflow for that tag. That
   publishes the tree here as one commit tagged `vX.Y.Z`.
5. Here, publish a GitHub release for that tag. `release.yml` checks the versions, runs CI, waits for
   approval in the `release` environment, then publishes to PyPI, npm, Maven Central and GitHub
   Packages and tags `go/vX.Y.Z` for the Go module.
