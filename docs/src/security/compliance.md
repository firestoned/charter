# Compliance design and control mapping

Status: design intent for review with Enterprise IAM, Technology Risk and
Internal Audit. The mappings below say which control objective each mechanism
supports; they are not a compliance attestation. Control references should be
confirmed against RBC's own control library before use.

## Principles

1. **Fail closed.** No change reaches Entra unless policy checks and the
   approval check both pass. Missing config means "deny", not "allow".
2. **Every change has a person, a reviewer and a ticket.** Requester and
   approver are recorded on the object and in every audit record, and must differ.
3. **Every external change is evidenced twice.** The controller's own audit
   log, and Entra's directory audit log for the controller's service principal.
   Reconciling the two is a detective control.
4. **Least privilege, no standing secrets.** Graph `Application.ReadWrite.OwnedBy`
   only; workload identity federation instead of a client secret.
5. **The IAMClient is the system of record for intent; Entra is converged to it.**
   Out-of-band changes in Entra are detected, audited and reverted.
6. **Admins create, owners maintain.** Creation, deletion and admin-only
   fields need a platform admin and a change reference. Owners may change
   redirect URIs themselves, within the redirect domain policy.

## How a change flows

**Create (admin only)**

```
Team request -> approval in the change system (requester != approver, CHG ref)
  -> platform admin adds a ResourceSetInputProvider in charter-system
     (requestedBy, approvedBy, changeRef, owners, ownerGroup, groups, ...)
  -> Flux ResourceSet, as the charter-provisioner SA, renders:
       IAMClient + Role/RoleBinding letting ownerGroup edit that one IAMClient
  -> admission: only admins/provisioner may create; author stamped
  -> controller: policy check -> approval check -> audited Graph calls
```

**Owner update (redirect URIs)**

```
Owner: kubectl edit / patch iamclient payments-portal  (RBAC: that object only)
  -> admission: only spec.redirectURIs may differ; https, allowed domain, no wildcard;
     last-modified-by stamped from the authenticated user
  -> controller: policy check; admin hash unchanged so no admin approval needed;
     audited Graph update records last_modified_by
```

**Admin change (owners, groups, rotation, Dex, deletion policy, display name)**

Admin updates the input provider with a new change reference. Admission blocks
anyone else from changing these fields. The controller backstops it: if the
hash of the admin-only fields changed and the change reference did not, it
stops with `Ready=False, reason=PendingApproval` and a `denied` audit record,
and applies nothing.

The Kubernetes API server audit log records every write to IAMClients with the
authenticated user; together with `last-modified-by` and the controller's
records (which carry the object's generation) this gives a full chain from
person to Entra change.

## Audit record

One JSON line per event on the `audit` log target (schema `charter.audit/v1`),
shipped to the SIEM with immutable retention, and mirrored as a Kubernetes Event.

| Field | Purpose |
|---|---|
| `seq`, `prev_hash` | Per-process sequence and SHA-256 chain; gaps or edits are detectable |
| `time`, `actor` | When, and which workload identity acted |
| `action`, `outcome` | e.g. `add_password` / `attempted`, `succeeded`, `failed`, `denied`, `info` |
| `subject` | Namespace, name, UID, generation, spec hash, admin-field hash, Entra uniqueName |
| `subject.last_modified_by` | Kubernetes user who last wrote the object, stamped by admission |
| `subject.requested_by`, `approved_by`, `change_ref` | Who asked, who approved, which change |
| `subject.correlation_id` | Ties all records from one reconcile together |
| `details` | Non-secret parameters (key IDs, fields changed, owner IDs) |

Mutations are logged as `attempted` before the call and `succeeded`/`failed`
after, so intent is recorded even if the process dies mid-call. Secret values
never appear: they are held in `SecretString` (redacted `Debug`, zeroized on drop).

Actions recorded: `policy_check`, `approval_check`, `create_application`,
`update_application`, `drift_detected`, `create_service_principal`,
`add_owner`, `remove_owner`, `add_password`, `deliver_secret`,
`remove_password`, `apply_push_secret`, `delete_push_secret`,
`delete_application`, `retain_application`, `cleanup`.

## Control mapping

| Control objective | Mechanism | Evidence an auditor can pull | SOX ITGC area | NIST SP 800-53 | OSFI B-13 domain |
|---|---|---|---|---|---|
| Changes are authorised before implementation | Creation and admin-only fields need an admin and a change reference (admission + controller backstop) | Change tickets, `approval_check` records, `status.changeRef`, API server audit log | Change management | CM-3, CM-5 | Technology operations (change management) |
| Owner self-service is bounded | Owners hold RBAC on their own IAMClient only; admission limits them to `redirectURIs` within allowed domains | Per-client Role/RoleBinding, VAP denials, `last_modified_by` in audit records | Logical access, change management | AC-3, AC-6, CM-5 | Cyber security (identity and access) |
| Separation of duties | Requester must differ from approver; controller cannot approve | Annotations and audit `subject` fields | Change management | AC-5 | Governance |
| Least privilege for automation | `Application.ReadWrite.OwnedBy`; owner set limited to spec + controller | Entra app role assignment for controller SP | Logical access | AC-6 | Cyber security (identity and access) |
| No standing credentials for automation | Workload identity federation; client-secret auth disabled unless `ALLOW_CLIENT_SECRET_AUTH=true` | Deployment manifest, absence of secrets on controller SP | Logical access | IA-5 | Cyber security |
| Credential lifecycle | Max lifetime policy, rotation at one-third remaining, grace window, revoke stale and unknown secrets | `add_password` / `remove_password` records, Entra keyCredential dates | Logical access | IA-5(1), AC-2 | Cyber security |
| Accountability for every app | At least one human owner required; owners reconciled | `add_owner` / `remove_owner` records, Entra owners list | Logical access | AC-2 | Governance |
| Configuration integrity | Drift detection on name, audience, group claims, redirect URIs, owners, secrets | `drift_detected` records | Change management | CM-3, CM-6, SI-7 | Technology operations |
| Secure redirect configuration | HTTPS only, allowed domain list, no wildcards, no loopback in prod | `policy_check` denials | Change management | SC-23, CM-7 | Cyber security |
| Audit logging content and protection | Structured records, hash chain, SIEM with immutable retention | SIEM query by `subject.uid` or `change_ref` | IT operations | AU-2, AU-3, AU-9, AU-12 | Cyber security (logging and monitoring) |
| Secret delivery to the vault | Optional `spec.pushSecret` (admin-only) renders an ESO `PushSecret` to an allow-listed `ClusterSecretStore`; the OpenBao path is fixed per client (`<prefix><namespace>/<name>`); the previous Entra secret is not revoked until the push after a rotation has synced; the OpenBao copy is deleted with the client | `apply_push_secret` / `delete_push_secret` records, `SecretPushed` condition, OpenBao audit device | Logical access | SC-28, IA-5(1) | Cyber security |
| Deprovisioning | `deletionPolicy: Retain` (default) revokes all secrets and keeps the app as evidence; `Delete` soft-deletes | `remove_password` / `delete_application` records | Logical access | AC-2(3) | Cyber security |
| Software supply chain integrity | cargo-deny (advisories, licences, sources), SBOM (CycloneDX + BuildKit), cosign keyless signature, SLSA provenance, digest-pinned image | CI run, Rekor entry, attestation | Change management (SDLC) | SR-4, SR-11, SI-7, SA-15 | Technology operations (SDLC) |

## Open items before production

- **Leader election and HA.** Run one active replica with leader election so a
  failover never produces two writers. Required for a tier-0 dependency.
- **OpenBao sink.** Opt-in delivery to OpenBao through an ESO `PushSecret`
  exists (`spec.pushSecret`), but the Kubernetes Secret is still always written
  because the PushSecret reads from it. Still open: making OpenBao the only
  copy, and splitting the Dex and Entra secrets. Until then, enable KMS
  encryption at rest and restrict Secret read RBAC.
- **Approval intake.** Today an admin creates the ResourceSetInputProvider by
  hand. Connect it to the change system (e.g. an ExternalService input
  provider backed by the approval API) so approvals are not retyped.
- **Admission policies in a real cluster.** The CEL in `deploy/admission-policy.yaml`
  has not been run against an API server yet, and MutatingAdmissionPolicy is
  beta; confirm availability on the target AKS version.
- **Flux field ownership.** Confirm that the ResourceSet does not revert
  owner-set `redirectURIs` (it should not, since it never sets that field).
- **Entra log reconciliation.** A scheduled job comparing Entra directory audit
  logs for the controller's SP against the controller's audit stream.
- **Egress restriction.** Allow only `login.microsoftonline.com`,
  `graph.microsoft.com` and the API server (FQDN-aware egress or proxy).
- **Group assignment.** Needs `AppRoleAssignment.ReadWrite.All`, a privileged
  permission IAM should approve separately; not implemented.
- **Retention periods.** Confirm audit log retention with Records Management.
- **Threat model and penetration test** before onboarding production teams.
- **Automated integration tests.** The end-to-end scenarios in the developer
  guide have been run by hand against a non-production tenant (create, drift,
  approval gate, rotation, OpenBao delivery, deletion). Still open: running
  them in CI, and rotation crash-recovery scenarios.
