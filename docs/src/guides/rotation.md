# Rotating secrets

Rotation is automatic. This page covers what to expect, how to change the
schedule, and how to rotate or revoke now.

## Scheduled rotation

Each secret lives for `spec.secretRotation` (default `90d`). When a third of
that is left, the controller:

1. creates a new Entra password (`add_password`, reason `rotation`),
2. writes it to the Secret (`deliver_secret`) and, with `pushSecret`, waits
   for External Secrets to push it to OpenBao,
3. keeps the previous password valid for the grace window
   (`ROTATION_GRACE_HOURS`, default 24),
4. revokes the previous password (`remove_password`, reason `rotated_out`).

| `secretRotation` | Rotates every | Each secret valid for |
|---|---|---|
| `90d` (default) | ~60 days | 90 days |
| `30d` | ~20 days | 30 days |
| `720h` | ~20 days | 30 days |
| `24h` | ~16 hours | 24 hours |

## Changing the schedule

`secretRotation` is admin-only: change it with a new change reference.

- **Shortening** it replaces the current secret immediately if that secret
  would outlive the new lifetime (`add_password`, reason `lifetime_shortened`).
  This is what you want after tightening policy: the long-lived secret does
  not linger.
- **Lengthening** it takes effect at the next rotation; the current secret
  keeps its original expiry.

The value must be at least `1h` and at most `MAX_SECRET_LIFETIME_DAYS`
(default 180 days); otherwise the client goes to `PolicyViolation`.

## Rotating now

Remove the secret value from the delivered Secret. The controller sees the
Secret is missing its `client-secret`, issues a new password and delivers it
within seconds:

```sh
kubectl -n team-payments patch secret payments-portal-entra --type json \
  -p '[{"op":"remove","path":"/data/client-secret"}]'
```

The audit trail shows `add_password` with reason `initial_or_missing`, then
`deliver_secret`. The previous password stays valid for the grace window, as
with a scheduled rotation.

## Revoking a leaked secret

The grace window keeps the previous secret valid, which is wrong for a leak.
Revoke the leaked password in Entra directly:

1. In the Entra admin center, open the app registration
   (`charter-<displayName>`), **Certificates & secrets**, and delete the
   leaked secret (match the key ID with the Secret's
   `iam.rbc.example/key-id` annotation).
2. Trigger a reconcile:
   ```sh
   kubectl -n team-payments label iamc payments-portal charter/poke=$(date +%s) --overwrite
   ```
3. The controller finds the delivered password gone, issues a new one and
   delivers it (`add_password`, reason `initial_or_missing`).

Consumers fail authentication between steps 1 and 3; that is the point.

!!! note "Within 10 minutes of a rotation"
    If the leaked key was delivered less than 10 minutes ago, the controller
    first assumes Graph has not caught up yet and waits until those 10 minutes
    have passed before replacing it. The leaked key is already revoked in
    Entra during that time.

## Checking rotation state

```sh
kubectl -n team-payments get iamc payments-portal \
  -o jsonpath='{.status.secretKeyId} {.status.secretExpiresAt}{"\n"}'
kubectl -n team-payments get secret payments-portal-entra \
  -o jsonpath='{.metadata.annotations}' | jq
```

The Secret's `iam.rbc.example/previous-key-id` is the key still inside its
grace window (or waiting for OpenBao), if any.
