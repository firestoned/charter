<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changing and deleting a client

## Admin-only changes

Every field except `redirectURIs` is admin-only: `displayName`, `owners`,
`groups`, `secretRotation`, `deletionPolicy`, `dex`, `pushSecret`. Change one
together with a **new** change reference (and, if they changed, the requester
and approver):

```sh
kubectl -n team-payments patch iamc payments-portal --type merge -p '
metadata:
  annotations:
    iam.rbc.example/change-ref: CHG0012400
spec:
  owners:
    - 11111111-1111-1111-1111-111111111111
    - 33333333-3333-3333-3333-333333333333
'
```

Through Flux, edit the input provider; it carries the change reference.

If the change reference is the same as the one in `status.changeRef`, the
controller stops with `Ready=False`, reason `PendingApproval`, and applies
nothing. Setting a new change reference resumes it.

## Deleting a client

```sh
kubectl -n team-payments delete iamc payments-portal
```

Through Flux, remove the input provider (or its approved label).

What happens in Entra depends on `spec.deletionPolicy`:

| Policy | Effect | Audit records |
|---|---|---|
| `Retain` (default) | Every client secret is revoked. The registration, its service principal and its owners stay, as evidence and for recovery. | `remove_password` (reason `deletion_policy_retain`), `retain_application` |
| `Delete` | The registration is deleted. Entra keeps it soft-deleted for 30 days, then removes it. | `delete_application` |

In both cases the `PushSecret` is deleted first (removing the OpenBao copy)
and the Secret is garbage-collected.

The finalizer `iam.rbc.example/entra-cleanup` keeps the `IAMClient` until this
succeeds. If Graph is unreachable the object stays `Terminating` and the
controller retries every 30 seconds.

!!! warning "Recreating a client deleted with `Delete`"
    A soft-deleted app keeps its `uniqueName`. Creating an `IAMClient` with the
    same namespace and name within 30 days fails with "Another object with the
    same value for property uniqueName already exists". Restore the app from
    **App registrations > Deleted applications** (Charter then adopts it), or
    permanently delete it there, before recreating. See
    [troubleshooting](troubleshooting.md#uniquename-already-exists).

## Retained registrations

A retained registration has no secrets and nobody can sign in with a secret
again, but it still exists. To reuse it, recreate the `IAMClient` with the
same namespace and name: the `uniqueName` matches, so Charter adopts it,
issues a new secret and resumes management. To remove it, delete it in the
Entra admin center.
