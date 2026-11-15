<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Troubleshooting

Start with the client's conditions and events:

```sh
kubectl -n <ns> get iamc <name> \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
kubectl -n <ns> describe iamc <name>          # Events mirror the audit records
kubectl -n charter-system logs deploy/charter-iam | grep '"reconcile failed"'
```

## Conditions

| Condition | Reason | Meaning | What to do |
|---|---|---|---|
| `Ready=True` | `Reconciled` | Entra matches the approved spec | Nothing |
| `Ready=False` | `PolicyViolation` | A policy rule failed; the message lists all of them | Fix the spec |
| `Ready=False` | `PendingApproval` | The approval gate failed | See below |
| `Ready=False` | `PushSecretFailed` | Entra is fine, but the push to OpenBao failed | See [OpenBao](#openbao-delivery) |
| `SecretPushed=False` | `Pending` | Waiting for External Secrets to push | Wait up to `PUSH_SECRET_REFRESH_INTERVAL` |

### PendingApproval messages

| Message | Cause |
|---|---|
| `missing requested-by` / `missing approved-by` / `missing change-ref` | An approval annotation is absent or empty |
| `separation of duties: approver is the requester` | Same person in both (case-insensitive) |
| `admin-only fields changed without a new change-ref` | An admin-only field changed but `change-ref` equals `status.changeRef` |

### PolicyViolation messages

| Message | Cause |
|---|---|
| `redirect URI must use https: ...` | `http://` or another scheme |
| `redirect host X is not in the allowed domains` | Host not under `ALLOWED_REDIRECT_DOMAINS` |
| `wildcard redirect URIs are not allowed: ...` | A `*` in the URI |
| `loopback redirect URIs are disabled by policy: ...` | `localhost` / `127.0.0.1` without `ALLOW_LOCALHOST_REDIRECTS=true` |
| `not an absolute URI: ...` | Missing scheme |
| `at least one human owner is required for accountability` | `spec.owners` is empty |
| `secretRotation must look like 90d or 720h, got ...` | Bad format, below 1 hour or above 730 days |
| `secretRotation Nd exceeds the policy maximum of Md` | Above `MAX_SECRET_LIFETIME_DAYS` |
| `dex issuer: ...` | `dex.issuerURL` breaks a redirect rule |
| `pushSecret: ClusterSecretStore X is not in the allowed push stores` | Store not in `ALLOWED_PUSH_SECRET_STORES` (or that list is empty) |
| `pushSecret: pushSecret has no clusterSecretStore and the controller has no default` | `pushSecret: {}` with no `DEFAULT_PUSH_SECRET_STORE` |

## Replication lag

Microsoft Graph is eventually consistent: for a few seconds after a write, a
read can return the old state, and a write can conflict with the previous one
still being applied. These errors are usually transient; the controller retries
after 30 seconds and converges. Each attempt still leaves a `failed` audit
record.

| Error | Typical moment |
|---|---|
| `403 Authorization_RequestDenied: ... the backing application of the service principal being created must in the local tenant` | Creating the service principal just after creating the app |
| `config: application missing right after upsert` | Reading the app back just after creating it |
| `409 Request_MultipleObjectsWithSameKeyValue: The service principal cannot be created ... already in use` | A retry creating a service principal that was in fact created |
| `400 Request_BadRequest: One or more added object references already exist for the following modified properties: 'owners'` | Re-adding an owner that a stale read did not show |
| `409 Directory_ConcurrencyViolation` | Two writes to the same app within about a second, for example removing two passwords |
| Log line `delivered key not visible in Graph yet; waiting for replication` | A reconcile right after a rotation; expected, not an error |

If one of these persists for more than a few minutes, it is not lag.

## Throttling

`429 Too Many Requests` means Graph is throttling the tenant or the
controller's app. The controller retries after 30 seconds. Small or new tenants
throttle sooner; other automation and portal use count against the same limits.

## uniqueName already exists

```text
graph 400 Bad Request: Another object with the same value for property uniqueName already exists.
```

The client's app was deleted with `deletionPolicy: Delete` within the last 30
days and is still soft-deleted, holding its `uniqueName`. Either restore it
from **App registrations > Deleted applications** (Charter adopts it on the
next reconcile) or permanently delete it there.

## Controller does not start

| Log | Cause |
|---|---|
| `config: AZURE_TENANT_ID not set` (or `AZURE_CLIENT_ID`) | Workload identity webhook did not inject, or variables missing locally |
| `config: workload identity required: AZURE_FEDERATED_TOKEN_FILE is not set` | No federated token and client-secret auth not enabled. In-cluster: check the pod label `azure.workload.identity/use: "true"` and the service account annotation |
| `graph 401` / `AADSTS700016` / `AADSTS70021` | Wrong client ID, or the federated credential's issuer or subject does not match the service account |
| Token works but every call is `403` | Admin consent for `Application.ReadWrite.OwnedBy` missing |

## OpenBao delivery

| Symptom | Cause |
|---|---|
| `SecretPushed=False Failed: external-secrets.io/v1alpha1 PushSecret is not installed in this cluster` | External Secrets Operator (or its CRDs) missing |
| `SecretPushed=False Failed: <message from External Secrets>` | The store rejected the write: check `kubectl get clustersecretstore` and the store's policy |
| `SecretPushed=False Pending` for a long time | External Secrets is not running, or `PUSH_SECRET_REFRESH_INTERVAL` is long. While pending, the previous Entra secret is not revoked |
| `403` on `pushsecrets` in the controller log | The controller's ClusterRole lacks the `external-secrets.io` rule |

## Harmless log lines

- `tried to reconcile object ... that was not found in local store`: a queued
  retry for an object that was just deleted.
- `client secret auth enabled; this is for local development only`: expected
  with `ALLOW_CLIENT_SECRET_AUTH=true`, never in production.
