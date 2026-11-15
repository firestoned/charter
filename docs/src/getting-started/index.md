<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Getting started

Charter needs three things: a Kubernetes cluster, an Entra tenant, and an
Entra identity for the controller itself. How you provide the last one is the
main difference between a trial and production.

| | Quickstart | Production |
|---|---|---|
| Cluster | Any local cluster (kind, k3d) | AKS, or any cluster whose service account issuer Entra can reach |
| Tenant | A **non-production** tenant you administer | Your organisation's tenant |
| Controller identity | App registration with a short-lived client secret (`ALLOW_CLIENT_SECRET_AUTH=true`) | Workload identity federation: no secret at all |
| Where the controller runs | `cargo run` on your machine | A `Deployment` in `charter-system` |
| Admission policy, Flux | Optional | Required |

Follow these pages in order:

1. [Prerequisites](prerequisites.md): tools, permissions and what to decide up front.
2. [Bootstrap the Entra identity](entra-bootstrap.md): create the controller's
   own app registration and grant it its one permission.
3. Either the [quickstart](quickstart.md) or the
   [production install](production-install.md).

!!! warning "Never trial Charter in a production tenant"
    With client-secret authentication the controller's credential is a
    long-lived secret on your workstation. Use a tenant created for
    development, where you hold Global Administrator and nothing else depends
    on it.
