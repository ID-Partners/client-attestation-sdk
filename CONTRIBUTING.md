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
(cd typescript && npm ci && npx tsc --noEmit && npx vitest run --coverage)
(cd java && mvn verify)
./verify-validation.sh      # the three validators return the same verdict on every case
./verify-interop.sh         # every port's credential passes the Java AS-side verifier
```

CI runs all of it except `verify-interop.sh`, which needs the AS-side verifier (`client-attestation`
0.1.0) installed in `~/.m2`. That isn't public yet, so run it yourself before you ask for a release, and
use `mvn verify -Pinterop` to include the Java round-trip tests.

Each port has a coverage floor (Go in `ci.yml`, Python in `pyproject.toml`, TypeScript in
`vitest.config.ts`, Java in `pom.xml`). They sit at what was measured when they were set. Raise one when
you add tests; don't lower one to get a change through.

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
