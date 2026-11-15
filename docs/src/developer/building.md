<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Building and testing

## Build

```sh
cargo build
cargo build --release
```

The `aws-lc-sys` dependency (via rustls) compiles C code and needs a C
compiler and CMake. It writes large temporary files: if `/tmp` is small, set
`TMPDIR` to a directory on a larger filesystem.

## Checks

Every CI step is a Makefile target, so it runs the same way locally:

```sh
make check            # fmt-check, lint, test, crd-check, license-check
make deny             # cargo-deny: advisories, licences, sources
make audit            # cargo-audit
make help             # everything else
```

## Unit tests

| Module | What is covered |
|---|---|
| `policy` | Redirect rules, approval verification and gate, hash stability, owner-editable fields not changing the admin hash, `pushSecret` being admin-only, push store resolution |
| `controller` | Duration parsing, drift diff, rotation decisions (`rotation`, `lifetime_shortened`, `initial_or_missing`) |
| `push` | `PushSecret` rendering, sync state from `Ready` and `refreshTime` |

Graph and Kubernetes interactions are covered by the
[end-to-end tests](e2e.md), not mocked.

## Regenerating the CRD

```sh
make crd          # writes deploy/crd.yaml with its licence header
make crd-check    # what CI runs: fails if the file is stale
```

Doc comments on the types in `src/crd.rs` become the field descriptions in
the CRD, and from there the [IAMClient reference](../reference/iamclient.md).

## Binary and container image

```sh
make dist         # static musl binary in dist/charter-iam
make image        # the controller image, compiled inside the image
```

The binary is statically linked against musl (target
`x86_64-unknown-linux-musl`, needs `musl-tools`). The image's runtime stage is
`cgr.dev/chainguard/static`, running as UID 65532. `BINARY_FROM=host` builds
the image over `dist/charter-iam` instead of compiling inside it; the kind
tests use this to reuse the host's cargo cache.

## Licence headers

Every source file, script, manifest, workflow and doc page starts with:

```text
Copyright (c) 2026 Erick Bourgeois, charter
SPDX-License-Identifier: Apache-2.0
```

in the file's comment syntax. `make license-check` enforces it.

## Releases

Publishing a GitHub release tagged `vX.Y.Z` stamps `X.Y.Z` into `Cargo.toml`
(`make set-version`), builds the binary and image, and attaches to the
release (`make release-assets`):

| Asset | Content |
|---|---|
| `charter-iam-linux-amd64` | The static binary |
| `charter-X.Y.Z.yaml` | Install bundle: CRD, controller RBAC and Deployment, image pinned by digest |
| `charter-X.Y.Z-admission-policy.yaml` | The admission policies |
| `charter-X.Y.Z-flux-resourceset.yaml` | The Flux provisioning path |
| `charter-iam.cdx.json`, `docker-sbom.json` | CycloneDX SBOMs of the crate and the image |
| `SHA256SUMS` | Checksums of every file |

Every asset carries a build-provenance attestation
(`gh attestation verify <file> --repo firestoned/charter`). The release logic
is proven on every build by `make release-assets-test` and `make set-version-test`.

## CI

| Workflow | Runs | What |
|---|---|---|
| `build.yaml` | PRs, main, releases | SPDX headers, signed commits, format, clippy, tests, CRD in sync, cargo-audit, cargo-deny, musl binary + SBOM, image (pushed, Cosign-signed, SBOM'd and attested outside PRs), release assets |
| `e2e.yaml` | PRs, main | `make kind-e2e-ci`: CRD, admission policies and the controller image in kind |
| `docs.yaml` | Changes to docs or deploy | Strict docs build; publishes to GitHub Pages from main |
| `codeql.yaml` | PRs, main, weekly | CodeQL for Rust, Actions and Python |
| `sast.yaml` | PRs, main | Semgrep (Rust, security audit, secrets, OWASP) |
| `scorecard.yaml` | main, weekly | OpenSSF Scorecard |
| `dependabot-auto-merge.yaml` | Dependabot PRs | Auto-merges patch and minor updates after the kind e2e passes; holds majors for review |

Third-party actions are pinned by commit SHA; Dependabot (`.github/dependabot.yml`)
keeps them, the crates, the base images and the docs toolchain current, each
with a 7-day cooldown.
