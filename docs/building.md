# Build and test from source

Each language directory builds independently. Run only the section for the port you are changing.
The cross-language checks require all four toolchains.

Commands use a POSIX shell on macOS or Linux. Python activation on Windows uses
`.venv\Scripts\Activate.ps1`. Java provides `mvnw.cmd` for Windows.

## Toolchains

| Port | Minimum runtime | Build tools | Declared in |
| --- | --- | --- | --- |
| Python | Python 3.11 | `venv`, pip and `build` for packaging. | [`python/pyproject.toml`](../python/pyproject.toml) |
| TypeScript | Node.js 20 | npm. TypeScript is installed with the development dependencies. | [`typescript/package.json`](../typescript/package.json) |
| Go | Go 1.25 | Go toolchain. | [`go/go.mod`](../go/go.mod) |
| Java | JDK 17 | Maven Wrapper, which downloads Maven 3.9.16. | [`java/pom.xml`](../java/pom.xml) and [`maven-wrapper.properties`](../java/.mvn/wrapper/maven-wrapper.properties) |

First-time dependency installation needs network access. Later offline builds need the required
dependencies and build tools already cached. Use the Maven Wrapper for Java so the Maven version
matches the release workflow.

## Clone

```bash
git clone https://github.com/ID-Partners/client-attestation-sdk.git
cd client-attestation-sdk
```

Maintainers working in the private source repository run the same commands from that repository's
root. See [Contributing](../CONTRIBUTING.md) for the change and review rules.

## Python

1. From the repository root, create an environment and install the test and packaging tools.

   ```bash
   cd python
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -e '.[test]' build
   ```

2. Run the tests and build the package.

   ```bash
   python -m pytest --cov
   python -m build
   ```

3. Inspect `dist/`. It contains `client_attestation_sdk-<version>-py3-none-any.whl` and
   `client_attestation_sdk-<version>.tar.gz`, where `<version>` is the contents of `VERSION`.
   A wheel is the installable Python package archive. The `.tar.gz` file is the source distribution.
   See the [Python packaging guide](https://packaging.python.org/en/latest/flow/) for these formats.

4. Install the wheel in a separate environment to check the packaged import.

   ```bash
   python -m venv /tmp/client-attestation-wheel-check
   /tmp/client-attestation-wheel-check/bin/python -m pip install dist/client_attestation_sdk-*-py3-none-any.whl
   /tmp/client-attestation-wheel-check/bin/python -c 'import client_attestation_sdk; print(client_attestation_sdk.__version__)'
   cd ..
   ```

Use the version in `VERSION` when the checkout has a different version. The optional HTTP-client
and AWS integrations have separate extras. See the [Python README](../python/README.md#install).
The coverage report must meet the 95% floor in `pyproject.toml`.

## TypeScript

1. From the repository root, install the locked dependencies.

   ```bash
   cd typescript
   npm ci
   ```

   `npm ci` uses `package-lock.json` and fails when it disagrees with `package.json`.
   See the [npm command documentation](https://docs.npmjs.com/cli/commands/npm-ci/).

2. Type-check, test and build.

   ```bash
   npx tsc --noEmit
   npm run coverage
   npm run test:edge
   npm run build
   ```

3. Check the built entry point and create the package archive.

   ```bash
   node --input-type=module -e 'import { ClientAttestation } from "./dist/index.js"; console.log(typeof ClientAttestation)'
   npm pack
   cd ..
   ```

The build writes JavaScript and declarations to `typescript/dist/`. `npm pack` creates
`idpartners-client-attestation-sdk-<version>.tgz`. Its `prepack` hook runs the build.
Neither command publishes the package. Applications use the package's ESM exports.
The validator entry point is `@idpartners/client-attestation-sdk/validator`.

`test:edge` runs the bundled SDK in Cloudflare's `workerd` runtime with Node compatibility
disabled. File evidence and the SPIRE CLI need Node. The coverage thresholds are in
[`vitest.config.ts`](../typescript/vitest.config.ts).

## Go

1. From the repository root, download dependencies and run checks.

   ```bash
   cd go
   go mod download
   go vet ./...
   go test -race -cover ./...
   go build ./...
   ```

2. Build the supplied resource-server example as a binary.

   ```bash
   mkdir -p bin
   go build -o bin/protected-resource ./examples/protected-resource
   cd ..
   ```

`go build ./...` compiles every package. It does not create a distributable SDK binary.
The SDK is a Go module compiled into the consuming application.
`go/bin/protected-resource` is a local demonstration with placeholder issuer configuration.
See [Examples](examples.md) before running it.

CI checks total coverage at 84% or above. Its total includes commands and examples.
Use `go mod tidy` when changing dependencies. It can update `go.mod` and `go.sum`.

## Java

1. From the repository root, build and run the tests.

   ```bash
   cd java
   ./mvnw -B clean verify
   ```

2. Inspect `target/`. It contains `client-attestation-sdk-<version>.jar`,
   `client-attestation-sdk-<version>-sources.jar` and `client-attestation-sdk-<version>-javadoc.jar`.
   Test reports are in `target/surefire-reports/`. The coverage report is
   `target/site/jacoco/index.html`.

3. Install the SDK into your local Maven repository for use by another local project.

   ```bash
   ./mvnw -B install
   cd ..
   ```

The SDK JAR is a library. It has no application entry point and does not bundle its runtime
dependencies. The consuming application's Maven build resolves those dependencies.
The coverage floors are in `pom.xml`.

## Cross-language validation

1. From the repository root, activate the Python environment created above. Ensure Node, Go and
   a JDK are on `PATH`.

   ```bash
   . python/.venv/bin/activate
   ./verify-validation.sh
   ```

2. Read the final result. The script writes one verdict file per language under `validation/out/`.
   `validation/check.py` fails if a verdict differs from its expected result. The inputs and
   [validation semantics](../validation/SEMANTICS.md) are shared by all four ports.

The script runs `npm ci` and a Java build. It replaces previous generated files under
`validation/out/`. It requires no live attester.

## Credential interoperability

1. Obtain the separate AS-side verifier source from its maintainer. The required Maven artifact is
   `com.pingidentity.ps.oidf:client-attestation:0.1.0`. It is not on Maven Central.

2. Build that source and install the artifact in your local Maven repository. The repository's
   [interop script](../verify-interop.sh) assumes a sibling checkout named `client-attestation`.

   ```bash
   (cd ../client-attestation && mvn install)
   ```

3. From this SDK repository's root, with the Python environment active, run the cross-language check.

   ```bash
   ./verify-interop.sh
   ```

4. Include the Java round-trip tests when verifying the Java port.

   ```bash
   (cd java && ./mvnw -B verify -Pinterop)
   ```

The scripts use fixed test keys. They replace generated files under `vectors/out/` and
`interop/out/`. They require no live attester. The supplied shell scripts use POSIX classpath
separators. The interop script also resolves the JDK through macOS `java_home` or `JAVA_HOME`.
Set `JAVA_HOME` to your JDK directory on Linux.

## Documentation and API checks

Run these from the repository root after installing dependencies and building the ports:

```bash
python3 scripts/features.py --check
python3 scripts/version.py check
python/.venv/bin/python scripts/api_surface.py --check
git diff --check
```

The feature check compares the generated tables with `docs/features.json`. The version check
compares the manifests and version constants with `VERSION`. The API check compares the public
names with `docs/api-surface/`. See [Contributing](../CONTRIBUTING.md#changing-the-public-api)
before updating an API snapshot.

The [CI workflow](../.github/workflows/ci.yml) selects language jobs according to the changed
paths. Release CI runs the full matrix. `verify-interop.sh` is a local release check because
the separate verifier is unpublished.

## Build configuration reference

These settings build the library. They do not configure an attester or token policy.
The commands above use the checked-in defaults.

| Port | Configuration file | Settings and effect |
| --- | --- | --- |
| Python | [`pyproject.toml`](../python/pyproject.toml) | `requires-python` sets the minimum interpreter. `dependencies` lists core runtime packages. `project.optional-dependencies` defines `requests`, `httpx`, `aws` and `test` extras. `build-system` selects setuptools. Coverage settings set the measured source and required floor. |
| TypeScript | [`package.json`](../typescript/package.json) | `engines.node` sets the supported Node version. `scripts` names build and test commands. `exports` defines the client and validator import paths. `files` defines the published archive contents. `prepack` compiles before packaging. |
| TypeScript | [`tsconfig.json`](../typescript/tsconfig.json) | Defines compilation targets, module handling, declarations, output directory and source selection. `stripInternal` removes internal declarations from the supported type files. |
| TypeScript | [`vitest.config.ts`](../typescript/vitest.config.ts) | Defines test selection and coverage thresholds. The edge test has a separate `test:edge` command. |
| Go | [`go.mod`](../go/go.mod) | Defines the module path, minimum Go version and dependencies. `go.sum` records downloaded module checksums. No SDK binary packaging step. |
| Java | [`pom.xml`](../java/pom.xml) | Defines the Java release, dependencies, test and coverage plugins, source/Javadoc archives and the optional `interop` profile. |
| Java | [Wrapper properties](../java/.mvn/wrapper/maven-wrapper.properties) | Pins the Maven distribution downloaded by `mvnw`. `JAVA_HOME` selects the JDK used by the wrapper. |
| Shared | [`VERSION`](../VERSION) | Source for the version update script. `scripts/version.py check` verifies the checked-in copies. |

The repository does not provide a container-image build or deployment chart for the SDK.
Build the consuming application's image with the selected SDK package and its runtime dependencies.
The [component references](configuration.md#component-references) identify optional runtime integrations.
