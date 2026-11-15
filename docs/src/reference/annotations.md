<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Annotations, labels and finalizers

## On the IAMClient

| Key | Kind | Set by | Meaning |
|---|---|---|---|
| `iam.rbc.example/requested-by` | annotation | Admin / Flux | Who requested the change |
| `iam.rbc.example/approved-by` | annotation | Admin / Flux | Who approved it; must differ from the requester |
| `iam.rbc.example/change-ref` | annotation | Admin / Flux | Change ticket; must change with every admin-only change |
| `iam.rbc.example/last-modified-by` | annotation | Admission (MutatingAdmissionPolicy) | Authenticated user of the last create or update; hand-set values are overwritten |
| `iam.rbc.example/entra-cleanup` | finalizer | Controller | Holds deletion until Entra cleanup succeeds |

## On the Secret `<name>-entra`

| Key | Kind | Meaning |
|---|---|---|
| `app.kubernetes.io/managed-by: charter-iam` | label | Marks Secrets the controller manages (and watches) |
| `iam.rbc.example/key-id` | annotation | Key ID of the delivered Entra password |
| `iam.rbc.example/previous-key-id` | annotation | Key ID delivered before the last rotation |
| `iam.rbc.example/rotated-at` | annotation | RFC 3339 time the current password was delivered |

The Secret has an owner reference to its `IAMClient`, so it is deleted with it.

## On the PushSecret `<name>-entra`

| Key | Kind | Meaning |
|---|---|---|
| `app.kubernetes.io/managed-by: charter-iam` | label | Managed by Charter |
| `iam.rbc.example/push-spec-hash` | annotation | Hash of the rendered spec; the `PushSecret` is re-applied, and audited, only when it changes |

It also has an owner reference to its `IAMClient`. The controller only
deletes a `PushSecret` whose owner reference matches the client's UID.

## On the Entra app registration

| Property | Value |
|---|---|
| `uniqueName` | `<NAME_PREFIX><namespace>-<name>` |
| `tags` | `charter`, `k8s:<namespace>/<name>`, `spec:<first 16 hex of the spec hash>` |
| `notes` | "Managed by charter-iam from IAMClient <ns>/<name>. Change <change-ref>. Do not edit by hand: changes are reverted and audited." |
| Password display name | `charter <YYYY-MM-DD>` |

Search the Entra admin center for the tag `charter` or the prefix to list
every Charter-managed registration.

## Flux

| Key | Where | Meaning |
|---|---|---|
| `iam.rbc.example/approved: "true"` | `ResourceSetInputProvider` label | Selects approved requests for the `iam-clients` ResourceSet |
