# Contributing

## The rule that matters

The four ports have to agree. A change in behaviour lands in every port that has the feature, in the same
pull request, and if the behaviour is observable it gets a case in `vectors/` or `validation/` so the
agreement is checked rather than assumed. A port that can't follow yet is marked in the feature matrix as
missing the feature, not quietly left behind: edit [`docs/features.json`](docs/features.json) and run
`python3 scripts/features.py`, which rewrites the table in the README and the explainer. CI fails if they
drift.

## Running everything

You need Go 1.25+, Python 3.11+, Node 20+ and a JDK 17+. Java and both `verify-*.sh` scripts build with
`java/mvnw`, which pins the Maven version, so you don't need Maven installed, except to build and install
the AS-side verifier that `verify-interop.sh` needs (below).
Set up the dependencies with [Build and test](docs/building.md) first. Commands below run from the
repository root.

```bash
(cd go && go vet ./... && go test -race -cover ./...)
. python/.venv/bin/activate
(cd python && python -m pytest --cov)
(cd typescript && npm ci && npx tsc --noEmit && npx vitest run --coverage && npm run test:edge)
(cd java && ./mvnw verify)
./verify-validation.sh      # the four validators return the same verdict on every case
./verify-interop.sh         # Go, Python and TypeScript credentials pass the Java AS-side verifier
python3 scripts/features.py --check
python3 scripts/version.py check
python/.venv/bin/python scripts/api_surface.py --check   # each port's public API matches docs/api-surface/
git diff --check
```

CI runs all of it except `verify-interop.sh`, which needs the AS-side verifier (`client-attestation`
0.1.0) installed in `~/.m2`. That isn't public yet, so run it yourself before you ask for a release, and
run `./mvnw verify -Pinterop` in `java/` for Java's own round trip through the same verifier.

CI runs on pull requests and on pushes to `main`, and both are path-filtered. A port's job runs when the
change touches that port's directory or its `docs/api-surface/<port>.txt`. The `validation` job (the
four-port agreement) runs when a change touches a validator or its `validate-emit` program. A change to
shared paths (`.github/`, `scripts/`, `vectors/`, `validation/`, `verify-*.sh`, `VERSION`) runs every job.
A docs-only change runs only the features and version checks. Pull requests test the oldest and newest
supported Python; pushes to `main` test all four. The required check is `ci-ok`.

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
that removes it) and remove it in the next major. The exception is a security fix that makes the SDK refuse
something it used to accept: it can ship in a minor or patch release under the security exception in the
README's [versioning policy](README.md#status-and-versioning), and its CHANGELOG entry goes under "Check
these before you upgrade". Experimental API can change in a minor release. If a
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

1. In the source repository, run `python3 scripts/version.py set X.Y.Z`. It writes `VERSION`
   and every version copy. Use the intended release version in place of `X.Y.Z`.
2. Move the completed `[Unreleased]` entries in `CHANGELOG.md` into a dated version section.
   Leave an empty `[Unreleased]` section for later changes.
3. Run the checks under [Running everything](#running-everything). Build the package artifacts
   using [Build and test](docs/building.md). Install the external verifier before running interop.
4. Merge the release change in the source repository. Tag that commit on `main` as `vX.Y.Z`.
   Dispatch `sync-public.yml` on `main` (not on the tag) with the version. The source repository's
   internal guide gives the command and required setup. The sync publishes one commit and `vX.Y.Z`
   to the public repository.
5. In `ID-Partners/client-attestation-sdk`, publish a GitHub release for that existing tag.
   [`release.yml`](.github/workflows/release.yml) checks versions and runs the full CI matrix.
6. Approve the jobs in the public repository's `release` environment. They publish to PyPI,
   npm and Maven Central. The Go job pushes `go/vX.Y.Z` for the submodule.
7. Check each job's result. The workflow does not publish packages from the private source
   repository. Source sync and package publishing are separate operations.

## Documentation changes

Use plain language and the API names exported by the port. State the command's working directory,
prerequisites and expected result. Label integration fragments that depend on application variables.
Complete examples must include imports and handle failures.

Check examples against the implementation and run complete offline examples before committing them.
Keep the root README's documentation links current. Add new public guides to the source repository's
public-path allowlist so they are included in the next sync. Feature tables are generated from
`docs/features.json` with `python3 scripts/features.py`; edit that file before regenerating the tables.
