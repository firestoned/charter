<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Concepts

How Charter works, from the outside in:

- [Architecture](architecture.md): the components and the trust boundaries between them.
- [The reconcile loop](reconcile-loop.md): what happens, in order, every time
  the controller looks at an `IAMClient`.
- [Approvals and change kinds](approval-model.md): why some changes need an
  admin and a change reference and others do not.
- [Secret lifecycle and rotation](secret-lifecycle.md): how client secrets are
  issued, delivered, rotated and revoked.
- [Drift detection](drift.md): what the controller compares, and what it does
  about differences.
- [Dex in front of Entra](dex.md): the optional Dex configuration Charter generates.

## Vocabulary

Client
:   One `IAMClient` resource, and everything Charter creates for it.

Admin-only field
:   Any `spec` field except `redirectURIs`. Changing one needs a platform admin
    and a new change reference.

Owner-editable field
:   `spec.redirectURIs`. The owning team changes it itself.

`uniqueName`
:   The Entra alternate key Charter gives each registration,
    `<prefix><namespace>-<name>`. Every Graph call addresses the app by it, so a
    lost status or a crash never creates a duplicate.

Delivered key
:   The Entra password whose secret is currently in the client's Kubernetes
    Secret. Its key ID is the Secret's `iam.rbc.example/key-id` annotation.

Grace window
:   How long the previously delivered secret stays valid after a rotation
    (`ROTATION_GRACE_HOURS`), so consumers can pick up the new one.
