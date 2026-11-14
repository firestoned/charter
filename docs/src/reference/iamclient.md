# IAMClient API

| | |
|---|---|
| Group | `iam.rbc.example` |
| Version | `v1alpha1` |
| Kind | `IAMClient` |
| Scope | Namespaced |
| Short name | `iamc` |
| Printer columns | `AppID`, `Ready`, `SecretExpires` |

The tables below are generated from `deploy/crd.yaml` when the docs are built.

## Spec

<!-- crd-fields: spec -->

### Who may change what

| Field | Editable by | Change needs |
|---|---|---|
| `redirectURIs` | Owning team or admin | Nothing beyond the redirect policy |
| Every other field | Platform admin only | A new `iam.rbc.example/change-ref` |

See [approvals and change kinds](../concepts/approval-model.md).

### Field notes

`displayName`
:   Shown to users on sign-in and consent screens, prefixed with
    `NAME_PREFIX` (default `charter-`).

`redirectURIs`
:   HTTPS only, no wildcards, host under an allowed domain. Order does not
    matter. With `dex` set they configure the Dex static client instead of Entra.

`groups`
:   Group names passed to Dex as a filter. Any non-empty list also sets the
    Entra app's `groupMembershipClaims` to `ApplicationGroup`. Charter does not
    assign the groups to the app.

`secretRotation`
:   A number and a unit: `d` (days), `h` (hours) or `m` (minutes). Between
    `1h` and `730d`, and not above the controller's `MAX_SECRET_LIFETIME_DAYS`.

`owners`
:   Entra **object IDs** (not UPNs) of users accountable for the registration.
    At least one is required.

`deletionPolicy`
:   `Retain` revokes all secrets and keeps the registration; `Delete` deletes
    it (soft-deleted for 30 days). See [deleting a client](../guides/change-and-delete.md#deleting-a-client).

`dex`
:   See [Dex in front of Entra](../concepts/dex.md).

`pushSecret`
:   See [delivering to OpenBao](../guides/openbao.md). `{}` uses the
    controller's default store.

## Status

<!-- crd-fields: status -->

See [status and conditions](status.md) for how to read these.

## Full example

```yaml
--8<-- "deploy/example-iamclient.yaml"
```
