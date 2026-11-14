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

These are what CI runs, in order:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo deny check                         # advisories, licences, sources
cargo run --locked -- crd | diff - deploy/crd.yaml
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
cargo run -- crd > deploy/crd.yaml
```

Doc comments on the types in `src/crd.rs` become the field descriptions in
the CRD, and from there the [IAMClient reference](../reference/iamclient.md).

## Container image

```sh
docker build -t charter-iam .
```

Two stages: `rust:1.97-bookworm` builds the release binary;
`gcr.io/distroless/cc-debian12:nonroot` runs it.

## CI

`.github/workflows/ci.yml`:

- **verify** (every PR and push): format, clippy, tests, `cargo-deny`, CRD in sync.
- **release** (main only): builds and pushes the image to
  `ghcr.io/firestoned/charter:<sha>` with a BuildKit SBOM and max provenance,
  generates a CycloneDX SBOM of the Rust dependencies, signs the image with
  keyless cosign, and attests SLSA build provenance.

`.github/workflows/docs.yaml` builds this site on PRs and publishes it to
GitHub Pages from main.
