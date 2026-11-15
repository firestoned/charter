<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Prerequisites

## Tools

| Tool | Used for |
|---|---|
| `kubectl` | Applying the CRD and manifests, inspecting clients |
| Azure CLI (`az`) | Creating the controller's app registration and granting consent |
| Rust toolchain (stable, edition 2024) | Building and running the controller locally |
| `kind` or similar | A local cluster for the quickstart |
| `helm` | Installing External Secrets Operator and OpenBao, if you want OpenBao delivery |

## Entra permissions

To bootstrap the controller you need, in the target tenant, a role that can
**grant admin consent for application permissions** to Microsoft Graph:
Global Administrator or Privileged Role Administrator.

The controller itself is granted exactly one Microsoft Graph **application**
permission:

| Permission | ID | Why |
|---|---|---|
| `Application.ReadWrite.OwnedBy` | `18a4783c-866b-4cc7-a460-3d5e5662c884` | Create app registrations, and read and change only the ones it owns. Creating a service principal for an owned app and managing owners and passwords on it are covered too. |

It holds no directory read permissions. It cannot list or modify any app it did
not create, which is why every registration has the controller among its owners.

## Decisions to make up front

These are controller-wide settings (see [configuration](../reference/configuration.md)):

- **Allowed redirect domains** (`ALLOWED_REDIRECT_DOMAINS`): the DNS suffixes
  your applications live under, for example `.apps.example.com`. Every redirect
  URI must be HTTPS on one of them. Leave it empty and every redirect URI is refused.
- **Name prefix** (`NAME_PREFIX`, default `charter-`): put on every display
  name and `uniqueName`, so Charter-managed registrations are easy to find.
- **Maximum secret lifetime** (`MAX_SECRET_LIFETIME_DAYS`, default 180).
- **Rotation grace** (`ROTATION_GRACE_HOURS`, default 24): how long the
  previous secret stays valid after a rotation.
- **OpenBao delivery** (optional): which `ClusterSecretStore`s clients may push
  to, and the path prefix. See [delivering to OpenBao](../guides/openbao.md).

## Who does what

| Role | Can |
|---|---|
| Platform admin (or the Flux provisioner identity) | Create and delete `IAMClient`s, change every field, set the approval annotations |
| Owning team | Change `spec.redirectURIs` of its own client only |
| Controller | Manage its finalizer and status, write Secrets and PushSecrets, call Graph |

See [RBAC and admission](../reference/rbac.md) for how this is enforced.
