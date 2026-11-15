<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Drift detection

The `IAMClient` is the system of record for intent; Entra is converged to it.
Any change made outside Charter, for example in the Entra admin center, is
detected, recorded and reverted on the next reconcile.

## What is compared

| Entra property | Desired value | On drift |
|---|---|---|
| `displayName` | `<NAME_PREFIX><spec.displayName>` | Reverted |
| `signInAudience` | `AzureADMyOrg` | Reverted |
| `groupMembershipClaims` | `ApplicationGroup` with `spec.groups`, else `None` | Reverted |
| `web.redirectUris` | `spec.redirectURIs`, or `<dex.issuerURL>/callback` with Dex (order ignored) | Reverted |
| Owners | `spec.owners` plus the controller | Missing added, extra removed |
| Passwords | The delivered one (plus the previous one in its grace window) | Extra revoked as `unknown_credential` |
| Service principal | Exists | Recreated |
| The app itself | Exists | Recreated (same `uniqueName`) |

Properties Charter does not manage, such as API permissions, app roles,
certificates, or optional claims, are not compared.

## What gets recorded

A drifted app produces:

```text
drift_detected   info       {"fields": ["displayName", "web.redirectUris"]}
update_application attempted {"fields": ["displayName", "web.redirectUris"]}
update_application succeeded {"fields": ["displayName", "web.redirectUris"]}
```

An unexpected owner produces `drift_detected` with `unexpectedOwner`, then
`remove_owner`. A hand-added password produces `remove_password` with reason
`unknown_credential`.

## How quickly

Drift is noticed on the next reconcile: at least hourly, or immediately when
anything on the `IAMClient` or its Secret changes. To force a check, add or
change a label:

```sh
kubectl -n <ns> label iamc <name> charter/poke=$(date +%s) --overwrite
```

A poke within a few seconds of the portal edit can miss it, because Graph
reads lag writes; the next scheduled pass catches it.

## Detecting drift without the controller

Charter's least privilege means it only sees apps it owns. To catch
registrations that were created by hand with a `charter-` prefix, or changes
Charter could not see, reconcile Entra's directory audit log for the
controller's service principal against the controller's own audit stream.
This detective control is listed under
[open items](../security/compliance.md#open-items-before-production).
