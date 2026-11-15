<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provisioning a client

Admins approve a client once. In production this goes through Flux, so the
approval is a reviewed change in Git; for testing an admin can apply an
`IAMClient` directly.

## Through Flux (recommended)

The `iam-clients` ResourceSet in `charter-system` renders, for each approved
request:

- the `IAMClient`, with the approval annotations,
- a `Role` and `RoleBinding` in the team's namespace that let the owning
  team's group `get`, `patch` and `update` that one `IAMClient` (and read its
  status), and nothing else.

To approve a request, add a `ResourceSetInputProvider` in `charter-system`
with the label `iam.rbc.example/approved: "true"`:

```yaml
apiVersion: fluxcd.controlplane.io/v1
kind: ResourceSetInputProvider
metadata:
  name: payments-portal
  namespace: charter-system
  labels:
    iam.rbc.example/approved: "true"
spec:
  type: Static
  defaultValues:
    name: payments-portal
    namespace: team-payments
    displayName: Payments Portal
    requestedBy: alice@example.com
    approvedBy: bob@example.com
    changeRef: CHG0012345
    owners: ["11111111-1111-1111-1111-111111111111"]
    ownerGroup: "22222222-2222-2222-2222-222222222222"
    groups: ["APP-Payments-Users", "APP-Payments-Admins"]
    secretRotation: 90d
    dexIssuerURL: https://dex.team-payments.apps.example.com
    pushSecretStore: openbao      # optional
```

| Input | Becomes |
|---|---|
| `name`, `namespace` | The `IAMClient` name and namespace |
| `displayName` | `spec.displayName` |
| `requestedBy`, `approvedBy`, `changeRef` | The approval annotations |
| `owners` | `spec.owners` (Entra user object IDs) |
| `ownerGroup` | Subject of the owner `RoleBinding` (the team's group as Kubernetes sees it) |
| `groups` | `spec.groups` |
| `secretRotation` | `spec.secretRotation` (default `90d`) |
| `deletionPolicy` | `spec.deletionPolicy` (default `Retain`) |
| `dexIssuerURL` | `spec.dex.issuerURL` |
| `pushSecretStore` | `spec.pushSecret.clusterSecretStore`, only when set |

The template deliberately has no `redirectURIs`. Flux applies with
server-side apply and owns only the fields it sets, so it does not revert the
redirect URIs the owning team adds afterwards.

!!! warning "Verify field ownership in your cluster"
    That Flux leaves owner-set `redirectURIs` alone, and that the optional
    `pushSecret` block renders cleanly when `pushSecretStore` is absent, have
    not yet been confirmed against a live Flux installation. Check both in a
    development cluster before relying on them.

## Directly with kubectl

An admin (or anyone, with the admission policy not installed) can apply an
`IAMClient`:

```yaml
apiVersion: iam.rbc.example/v1alpha1
kind: IAMClient
metadata:
  name: payments-portal
  namespace: team-payments
  annotations:
    iam.rbc.example/requested-by: alice@example.com
    iam.rbc.example/approved-by: bob@example.com
    iam.rbc.example/change-ref: CHG0012345
spec:
  displayName: Payments Portal
  redirectURIs: [https://payments.apps.example.com/callback]
  owners: [11111111-1111-1111-1111-111111111111]
```

The owning team then needs its own `Role` to edit redirect URIs; copy it from
the ResourceSet template.

## Checking the result

```sh
kubectl -n team-payments get iamc payments-portal
kubectl -n team-payments get iamc payments-portal -o jsonpath='{.status}' | jq
kubectl -n team-payments get events --field-selector involvedObject.name=payments-portal
```

`Ready=True` with reason `Reconciled` means the registration matches the spec
and the Secret is in place. Anything else: see [troubleshooting](troubleshooting.md).

## Choosing values

- **`displayName`** becomes `<NAME_PREFIX><displayName>` in Entra; keep it
  recognisable to users, since it appears on the consent and sign-in screens.
- **`owners`** are accountable for the registration in Entra. Use people, not
  service accounts, and keep at least two so one leaver does not orphan it.
- **`secretRotation`**: shorter is safer but means more restarts for consumers
  that do not reload secrets. `90d` with the default 24-hour grace is a common start.
- **`deletionPolicy`**: keep `Retain` unless the registration must disappear.
  See [changing and deleting](change-and-delete.md).
