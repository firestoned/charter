# Copyright (c) 2026 Erick Bourgeois, charter
# SPDX-License-Identifier: Apache-2.0

# Controller image. Static musl binary on a distroless static base, non-root.
#
# BINARY_FROM selects where the binary comes from. `container` (the default,
# `make image`) compiles it inside the image from the source tree, so nothing but
# a container runtime is needed. `host` copies `dist/charter-iam`, built by the
# host's cargo (`make dist`), so CI and the kind tests reuse the host's build
# cache and still ship exactly this runtime stage.
ARG BINARY_FROM=container

FROM rust:1-slim AS build-container
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools cmake make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/charter-iam /charter-iam

FROM scratch AS build-host
COPY dist/charter-iam /charter-iam

FROM build-${BINARY_FROM} AS build

FROM cgr.dev/chainguard/static:latest
COPY --from=build /charter-iam /usr/bin/charter-iam
USER 65532:65532
ENTRYPOINT ["/usr/bin/charter-iam"]
