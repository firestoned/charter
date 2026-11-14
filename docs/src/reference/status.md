# Status and conditions

## Fields

| Field | Meaning |
|---|---|
| `appId` | Application (client) ID |
| `objectId` | Directory object ID of the app registration |
| `servicePrincipalId` | Object ID of the service principal |
| `secretName` | The Secret holding the credentials (`<name>-entra`) |
| `secretKeyId` | Key ID of the delivered password |
| `secretExpiresAt` | When the delivered password expires (RFC 3339) |
| `pushSecretName` | The `PushSecret`, when `spec.pushSecret` is set |
| `pushedTo` | `<clusterSecretStore>:<remote key>`, when `spec.pushSecret` is set |
| `observedGeneration` | The `metadata.generation` this status describes |
| `appliedSpecHash` | Hash of the full spec last applied |
| `appliedAdminHash` | Hash of the admin-only fields last applied |
| `approvedBy` | Approver of the admin-only state currently applied |
| `changeRef` | Change reference the admin-only state was applied under |
| `conditions` | See below |

`approvedBy` and `changeRef` change only with admin changes. An owner's
redirect URI change keeps the approval the admin state was applied under.

## Conditions

### Ready

| Status | Reason | Set when |
|---|---|---|
| `True` | `Reconciled` | Entra matches the approved spec and the Secret is delivered |
| `False` | `PolicyViolation` | A policy rule failed; nothing was changed in Entra |
| `False` | `PendingApproval` | The approval gate failed; nothing was changed in Entra |
| `False` | `PushSecretFailed` | Entra is reconciled but the push to OpenBao failed |

### SecretPushed

Present only when `spec.pushSecret` is set.

| Status | Reason | Set when |
|---|---|---|
| `True` | `Synced` | External Secrets pushed the Secret after the last rotation |
| `False` | `Pending` | No push yet since the last rotation; the previous Entra secret is held back |
| `False` | `Failed` | External Secrets reports the `PushSecret` not ready, or its CRD is missing |

`lastTransitionTime` only changes when the condition's status flips, so it
says how long the client has been ready or not.

## Useful queries

```sh
# All clients that are not ready, with reason
kubectl get iamc -A -o json | jq -r '.items[] |
  select(any(.status.conditions[]?; .type=="Ready" and .status!="True")) |
  "\(.metadata.namespace)/\(.metadata.name) \(.status.conditions[] | select(.type=="Ready") | .reason)"'

# Secrets expiring in the next 30 days
kubectl get iamc -A -o json | jq -r --arg t "$(date -u -v+30d +%FT%TZ 2>/dev/null || date -u -d '+30 days' +%FT%TZ)" \
  '.items[] | select(.status.secretExpiresAt < $t) | "\(.metadata.namespace)/\(.metadata.name) \(.status.secretExpiresAt)"'
```
