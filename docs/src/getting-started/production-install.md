<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Production install

This installs the controller in-cluster with workload identity, the admission
policies that enforce "admins create, owners maintain", and the Flux
ResourceSet that admins provision through.

## Before you start

- [The Entra identity](entra-bootstrap.md) exists with
  `Application.ReadWrite.OwnedBy` and a **federated credential** for
  `system:serviceaccount:charter-system:charter-iam`.
- The cluster runs the
  [Azure Workload Identity](https://azure.github.io/azure-workload-identity/)
  webhook (built into AKS with `--enable-workload-identity`).
- Kubernetes 1.36 or later, where both `ValidatingAdmissionPolicy` and
  `MutatingAdmissionPolicy` are GA (`admissionregistration.k8s.io/v1`). On older
  clusters replicate the mutating policy with Kyverno.
- Flux with the Flux Operator (`ResourceSet`, `ResourceSetInputProvider`), if
  admins provision through Git.
- Optionally External Secrets Operator and OpenBao for
  [OpenBao delivery](../guides/openbao.md).

## 1. Namespace, CRD and RBAC

```sh
kubectl create namespace charter-system
kubectl apply -f deploy/crd.yaml
```

Edit `deploy/rbac.yaml` and set the service account annotation to the
controller's client ID:

```yaml
metadata:
  annotations:
    azure.workload.identity/client-id: "<controller-client-id>"
```

```sh
kubectl apply -f deploy/rbac.yaml
```

## 2. The controller

`deploy/deployment.yaml` runs one replica (there is no leader election yet, so
do not scale it). Review and set:

| Setting | What to put |
|---|---|
| `image` | The signed image **by digest**, `ghcr.io/firestoned/charter@sha256:...`. Verify the cosign signature at admission. |
| `ALLOWED_REDIRECT_DOMAINS` | Your application DNS suffixes |
| `MAX_SECRET_LIFETIME_DAYS`, `ROTATION_GRACE_HOURS` | Your credential policy |
| `ALLOWED_PUSH_SECRET_STORES`, `DEFAULT_PUSH_SECRET_STORE` | Store names, or remove both to disable OpenBao delivery |

The pod label `azure.workload.identity/use: "true"` makes the webhook inject
the token file and the `AZURE_*` variables. Do **not** set
`ALLOW_CLIENT_SECRET_AUTH`.

```sh
kubectl apply -f deploy/deployment.yaml
kubectl -n charter-system logs deploy/charter-iam | head
```

## 3. Admission policies

Edit the `iamclient-policy` ConfigMap in `deploy/admission-policy.yaml`:

- `provisioners`: Kubernetes usernames allowed to create clients (the Flux
  provisioner service account),
- `adminGroups`: group names or IDs of platform admins,
- `allowedRedirectDomains`: the same list as the controller's.

```sh
kubectl apply -f deploy/admission-policy.yaml
```

What it enforces is described in [RBAC and admission](../reference/rbac.md).

## 4. Flux provisioning

```sh
kubectl apply -f deploy/flux/resourceset.yaml
```

This creates the `charter-provisioner` service account and the `iam-clients`
ResourceSet. Each approved client is one `ResourceSetInputProvider` labelled
`iam.rbc.example/approved: "true"`; see [provisioning a client](../guides/provisioning.md).

## 5. Ship the audit log

The controller writes audit records to stdout on the `audit` log target, one
JSON object per line. Route them to your SIEM with immutable retention, kept
separate from debug logs. See [audit records](../reference/audit.md).

## 6. Verify

```sh
kubectl -n charter-system logs deploy/charter-iam | grep '"starting charter-iam"'
```

The log line shows the loaded policy. Then provision a test client and check
that it reaches `Ready=True` and its Secret appears.

## Hardening checklist

- [ ] Image pinned by digest and its signature verified at admission.
- [ ] Egress restricted to `login.microsoftonline.com`, `graph.microsoft.com`
      and the API server.
- [ ] Kubernetes Secrets encrypted at rest with KMS, and read access to
      `*-entra` Secrets limited to the consuming workloads.
- [ ] Audit log shipped to immutable storage, alerting on `failed` and `denied`.
- [ ] Entra directory audit logs for the controller's service principal
      reconciled against the controller's audit stream.
- [ ] The open items in [compliance](../security/compliance.md#open-items-before-production) reviewed.
