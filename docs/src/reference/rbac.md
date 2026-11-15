<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# RBAC and admission

## Who may do what

| Actor | Identity | May |
|---|---|---|
| Platform admin | Member of an `adminGroups` group | Create, delete, change every field, set approval annotations |
| Flux provisioner | `system:serviceaccount:charter-system:charter-provisioner` | Same as an admin, plus create the per-client owner `Role` |
| Owning team | The `ownerGroup` bound by the per-client `RoleBinding` | `get`, `patch`, `update` its one `IAMClient`; only `redirectURIs` may differ |
| Controller | `system:serviceaccount:charter-system:charter-iam` | Finalizer and status, Secrets, PushSecrets, Events |

## Controller ClusterRole

```yaml
--8<-- "deploy/rbac.yaml"
```

The controller cannot create or delete `IAMClient`s, and it has no access to
Roles, RoleBindings or anything outside the resources listed.

## Owner Role (per client)

Rendered by the ResourceSet in the client's namespace:

```yaml
rules:
  - apiGroups: ["iam.rbc.example"]
    resources: ["iamclients"]
    resourceNames: ["<name>"]
    verbs: ["get", "patch", "update"]
  - apiGroups: ["iam.rbc.example"]
    resources: ["iamclients/status"]
    resourceNames: ["<name>"]
    verbs: ["get"]
```

RBAC alone would let the owner change any field; the admission policy narrows
it to `redirectURIs`.

## Admission policy

`deploy/admission-policy.yaml` installs two policies, parameterised by the
`iamclient-policy` ConfigMap in `charter-system`:

| ConfigMap key | Meaning |
|---|---|
| `provisioners` | Comma-separated usernames allowed to provision |
| `adminGroups` | Comma-separated admin groups |
| `allowedRedirectDomains` | Comma-separated allowed domains (with leading dot) |

### `iamclient-admin-gates` (ValidatingAdmissionPolicy)

Applies to every create, update and delete of an `IAMClient`, except by the
controller's own service account:

1. Only admins and provisioners may **create** or **delete**.
2. On update, a non-admin may only change `spec.redirectURIs`. The compared
   fields are `displayName`, `owners`, `groups`, `secretRotation`,
   `deletionPolicy`, `dex` and `pushSecret`.
3. On update, a non-admin may not change the approval annotations.
4. Every redirect URI must be a URL, HTTPS, without `*`, on an allowed domain.

The binding uses `validationActions: [Deny, Audit]` and denies if the
ConfigMap is missing (`parameterNotFoundAction: Deny`).

!!! warning "Keep the field list in step"
    The list in rule 2 must match `OWNER_EDITABLE` in `src/policy.rs`: every
    field not listed there is admin-only. If a new field is missed here, the
    controller's admin-hash check still blocks the change without a new
    change reference, but the write is accepted at admission.

### `iamclient-stamp-author` (MutatingAdmissionPolicy)

On every create and update (except by the controller), sets
`iam.rbc.example/last-modified-by` to the authenticated username, overwriting
any value supplied. The controller copies it into every audit record.

`MutatingAdmissionPolicy` is GA (`admissionregistration.k8s.io/v1`) from
Kubernetes 1.36, which serves no other version. On older clusters replace it
with an equivalent Kyverno mutate rule.

Both policies are exercised against a real API server on every PR by the
[kind tests](../developer/e2e.md#kind-tier).

```yaml
--8<-- "deploy/admission-policy.yaml"
```
