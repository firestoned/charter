# entra-controller

A small kube-rs controller that turns an `IAMClient` custom resource into an
Entra ID app registration, its service principal, a rotated client secret, and
the Dex config that fronts it. Part of the IAM-as-a-Service proposal.

Status: scaffold. It compiles, unit tests pass, and the Graph calls follow the
v1.0 API, but it has not run against a real tenant yet.

## Prior art (checked 2026-11-12)

| Option | Manages Entra apps? | Notes |
|---|---|---|
| CAPZ (Cluster API Azure) | No | Uses Entra/workload identity to provision clusters; no app-registration CRDs. "CAPA" is the AWS provider. |
| Azure Service Operator v2 | Yes, recently | `entra.azure.com` `Application` since v2.21.0 (2026-08-31), `ServicePrincipal` since v2.22.0 (2026-11-02), plus `SecurityGroup`. No federated credential or client secret resource found. Go. |
| Crossplane provider-azuread (Upbound) | Yes, broadest | Applications, service principals, federated identity credentials, passwords. Terraform-based (Upjet), so it carries a heavy runtime. |
| This controller | Yes, narrow | One opinionated CR that also does secret delivery, rotation and Dex config, which none of the above do. |

**Reuse options.** If RBC already runs ASO or Crossplane, the cheapest path is a
thin controller (or a Crossplane Composition / KRO definition) that emits ASO
`Application` + `ServicePrincipal` objects and only adds the parts they lack:
secret rotation into OpenBao and Dex config. This controller calls Graph
directly so it has no dependency on either, but the reconcile shape is the same
and the Graph module can be swapped for "write ASO objects" later.

## Design

```
IAMClient (team namespace)
   │ reconcile (finalizer: iam.rbc.example/entra-cleanup)
   ├─ Graph: PATCH /applications(uniqueName='iamaas-<ns>-<name>')  Prefer: create-if-missing
   ├─ Graph: ensure servicePrincipals(appId=...), add owners
   ├─ Graph: addPassword when a third of the lifetime remains, then removePassword(old)
   ├─ Secret <name>-entra: tenant-id, client-id, client-secret, issuer, dex-config.yaml
   └─ status: appId, objectId, servicePrincipalId, secretKeyId, secretExpiresAt, Ready
```

Decisions worth knowing:

- **Idempotency via `uniqueName`.** Graph's upsert keyed on an alternate key
  means a lost status or a crash mid-reconcile never creates a duplicate app.
- **Naming guardrail.** Every app is `NAME_PREFIX` + namespace + name, and the
  display name is prefixed too, so IAM can see at a glance what the platform owns.
- **Least privilege.** The controller only needs `Application.ReadWrite.OwnedBy`.
  Apps it creates are owned by it, so it cannot touch anything else.
- **No stored credential.** Auth is workload identity federation: the projected
  service account token is exchanged for a Graph token. `AZURE_CLIENT_SECRET` is
  accepted for local dev only.
- **Dex in front.** With `spec.dex.issuerURL` set, Entra only sees
  `<issuer>/callback`; the team's own redirect URIs go into the Dex static
  client. Without `dex`, they go straight onto the Entra app.
- **Rotate, deliver, then revoke.** A new secret is written to the Kubernetes
  Secret before the old Entra password is removed.
- **Delete.** The finalizer deletes the app registration; Entra keeps it
  soft-deleted for 30 days, so mistakes are recoverable.

## Not done yet

- OpenBao sink (KV v2) instead of, or as well as, the Kubernetes Secret. The
  Entra secret and the Dex static-client secret share one Secret today; split them.
- Group assignment. `groups` currently drives the Dex group filter and switches
  Entra to `ApplicationGroup` claims. Assigning groups to the app needs
  `AppRoleAssignment.ReadWrite.All`, which IAM should approve separately.
- A Dex config renderer that merges per-client fragments into one Dex per team.
- Admission policy (allowed redirect domains per namespace, privileged groups
  need approval), events, metrics, leader election.
- Machine-to-machine: client credentials against Entra directly, since Dex has
  no client credentials grant.
- Integration test against a dev tenant.

## Run

```sh
cargo run -- crd > deploy/crd.yaml        # regenerate the CRD
kubectl apply -f deploy/crd.yaml -f deploy/rbac.yaml -f deploy/deployment.yaml
kubectl apply -f deploy/example-iamclient.yaml

# local dev against a test tenant
AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... cargo run
```
