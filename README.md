# Charter

*A charter is a grant of rights from an authority: platform admins grant an
identity client, and the owning team operates within it.*

`charter-iam` is a small kube-rs controller that turns an `IAMClient` custom resource into an
Entra ID app registration, its service principal, a rotated client secret, and
the Dex config that fronts it. Part of the IAM-as-a-Service proposal.

Built audit- and compliance-first for a tier 1 bank: nothing changes in Entra
without a policy check and a verified approval, and every change is audited.
See [docs/compliance.md](docs/compliance.md) for the control mapping.

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
IAMClient (created by admins via Flux ResourceSet; owners edit redirectURIs via the Kubernetes API)
   │ reconcile (finalizer: iam.rbc.example/entra-cleanup)
   ├─ 1. policy check     redirect domains, HTTPS, no wildcards, max secret lifetime, >=1 owner
   ├─ 2. approval check   create or admin-field change: requested-by != approved-by, new change-ref
   │                      redirectURIs-only change: owner's authority, author stamped by admission
   │     (either failing: Ready=False, audit "denied", no Entra change)
   ├─ 3. read Entra state; create, or record drift and correct it
   ├─ 4. service principal; owners = spec.owners + controller (extras removed)
   ├─ 5. client secret: new at 1/3 lifetime left, deliver, then revoke stale and unknown secrets
   ├─ 6. Secret <name>-entra: tenant-id, client-id, client-secret, issuer, dex-config.yaml
   └─ 7. status: appId, servicePrincipalId, secret key/expiry, appliedSpecHash, approvedBy, changeRef
every Entra mutation: audit "attempted" -> call -> "succeeded"/"failed" (JSON + Kubernetes Event)
```

Decisions worth knowing:

- **Fail closed.** Approval is required unless `REQUIRE_APPROVAL=false`;
  redirect domains must be allow-listed; loopback redirects are off by default.
- **Admins create, owners maintain.** Creating, deleting, or changing any
  admin-only field (everything except `redirectURIs`) needs a platform admin
  and a change reference. The owning team can change `redirectURIs` itself
  through the Kubernetes API; admission stamps who did it and the redirect
  domain policy still applies. See `deploy/admission-policy.yaml`.
- **Delivery.** Admins approve by adding a `ResourceSetInputProvider`; a Flux
  `ResourceSet` renders the `IAMClient` and a per-client Role for the owning
  team (`deploy/flux/resourceset.yaml`).
- **Idempotency via `uniqueName`.** Graph's upsert keyed on an alternate key
  means a lost status or a crash mid-reconcile never creates a duplicate app.
- **Drift is corrected and audited.** Portal edits to name, audience, group
  claims, redirect URIs, owners or secrets are reverted with a `drift_detected` record.
- **Least privilege.** Only `Application.ReadWrite.OwnedBy`, so the controller
  cannot touch apps it did not create.
- **No stored credential.** Workload identity federation. Client-secret auth
  exists only for local dev behind `ALLOW_CLIENT_SECRET_AUTH=true`.
- **Crash-safe rotation.** The delivered key ID lives on the Secret; any Entra
  password that is not the delivered one (or the previous one inside the grace
  window) is revoked, which also removes hand-added secrets.
- **Dex in front.** With `spec.dex.issuerURL` set, Entra only sees
  `<issuer>/callback`; the team's redirect URIs go into the Dex static client.
- **Retain by default on delete.** Secrets are revoked, the registration stays
  as evidence. `deletionPolicy: Delete` soft-deletes it (30 days in Entra).

## Not done yet

See "Open items before production" in [docs/compliance.md](docs/compliance.md):
leader election, OpenBao sink, the approval stamping job, Entra audit log
reconciliation, egress restriction, group assignment, integration tests.

## Run

```sh
cargo run -- crd > deploy/crd.yaml        # regenerate the CRD
kubectl apply -f deploy/crd.yaml -f deploy/rbac.yaml -f deploy/deployment.yaml

kubectl apply -f deploy/admission-policy.yaml -f deploy/flux/resourceset.yaml

# local dev against a non-production tenant only
ALLOW_CLIENT_SECRET_AUTH=true AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
  ALLOWED_REDIRECT_DOMAINS=.dev.example.com cargo run
```
