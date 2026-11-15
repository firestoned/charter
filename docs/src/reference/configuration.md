<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Controller configuration

The controller is configured through environment variables. It logs the
policy it loaded at startup (`starting charter-iam`).

## Entra authentication

| Variable | Default | Meaning |
|---|---|---|
| `AZURE_TENANT_ID` | required | Tenant to manage. Injected by the workload identity webhook. |
| `AZURE_CLIENT_ID` | required | The controller's own app registration. Injected by the webhook. Also the `actor` in audit records. |
| `AZURE_FEDERATED_TOKEN_FILE` | | Path of the projected service account token. When set, workload identity federation is used. Injected by the webhook. |
| `AZURE_AUTHORITY_HOST` | `https://login.microsoftonline.com/` | Token endpoint host. Injected by the webhook. |
| `ALLOW_CLIENT_SECRET_AUTH` | `false` | `true` allows `AZURE_CLIENT_SECRET` when no federated token is present. Development only. |
| `AZURE_CLIENT_SECRET` | | The controller's client secret, read only with `ALLOW_CLIENT_SECRET_AUTH=true`. |

Without a federated token file and without `ALLOW_CLIENT_SECRET_AUTH=true`
the controller refuses to start.

## Policy

| Variable | Default | Meaning |
|---|---|---|
| `NAME_PREFIX` | `charter-` | Prefix on display names and `uniqueName`s |
| `ALLOWED_REDIRECT_DOMAINS` | empty (nothing allowed) | Comma-separated domains; a redirect host must equal one or be under it. A leading dot is optional. |
| `ALLOW_LOCALHOST_REDIRECTS` | `false` | Allow `localhost` and `127.0.0.1` redirect URIs (any scheme) |
| `MAX_SECRET_LIFETIME_DAYS` | `180` | Upper bound for `spec.secretRotation` |
| `REQUIRE_APPROVAL` | `true` | Only the exact value `false` disables the approval gate |

## Rotation

| Variable | Default | Meaning |
|---|---|---|
| `ROTATION_GRACE_HOURS` | `24` | How long the previous secret stays valid after a rotation |

## OpenBao delivery

| Variable | Default | Meaning |
|---|---|---|
| `ALLOWED_PUSH_SECRET_STORES` | empty (no pushing) | Comma-separated `ClusterSecretStore` names clients may push to |
| `DEFAULT_PUSH_SECRET_STORE` | | Store used by `pushSecret: {}` |
| `PUSH_SECRET_PATH_PREFIX` | `charter/` | Remote key prefix; the key is `<prefix><namespace>/<name>` |
| `PUSH_SECRET_REFRESH_INTERVAL` | `1m` | `PushSecret.spec.refreshInterval` |

Changing `PUSH_SECRET_PATH_PREFIX` or the refresh interval re-renders every
`PushSecret` on the next reconcile, which is audited as `apply_push_secret`.

## Logging and identity

| Variable | Default | Meaning |
|---|---|---|
| `RUST_LOG` | `info` | Log filter. `info,audit=info` in production; keep the `audit` target at `info` or lower. |
| `POD_NAME` | | Reported as the Kubernetes Event reporter instance |

## Built-in timings

Not configurable:

| Timing | Value |
|---|---|
| Graph HTTP timeout | 30 seconds |
| Token refresh | 5 minutes before expiry |
| Requeue after an error | 30 seconds (5 minutes for invalid objects) |
| Requeue while a push is pending | 30 seconds |
| Wait for a just-delivered key to appear in Graph | 15 seconds, for up to 10 minutes |
| Drift check | At least hourly |
| Rotation lifetime tolerance | 5 minutes |

## Example

```yaml
--8<-- "deploy/deployment.yaml"
```
