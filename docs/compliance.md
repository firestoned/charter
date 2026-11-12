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
5. **Git is the system of record for intent; Entra is converged to it.**
   Out-of-band changes are detected, audited and reverted.

## How a change flows

```
Developer PR (IAMClient YAML)
  -> branch protection: CODEOWNERS review by Enterprise IAM for prod namespaces
  -> merge pipeline stamps annotations: requested-by, approved-by, change-ref,
     approved-spec-hash (from `entra-controller spec-hash`)
  -> GitOps applies (only identity allowed by ValidatingAdmissionPolicy)
  -> controller: policy check -> approval check -> audited Graph calls
  -> status records appliedSpecHash, approvedBy, changeRef
```

If anyone edits the spec without a new approval, the hash no longer matches and
the controller stops with `Ready=False, reason=PendingApproval` and a `Denied`
audit record. It does not partially apply.

## Audit record

One JSON line per event on the `audit` log target (schema `iamaas.audit/v1`),
shipped to the SIEM with immutable retention, and mirrored as a Kubernetes Event.

| Field | Purpose |
|---|---|
| `seq`, `prev_hash` | Per-process sequence and SHA-256 chain; gaps or edits are detectable |
| `time`, `actor` | When, and which workload identity acted |
| `action`, `outcome` | e.g. `add_password` / `attempted`, `succeeded`, `failed`, `denied`, `info` |
| `subject` | Namespace, name, UID, generation, spec hash, Entra uniqueName |
| `subject.requested_by`, `approved_by`, `change_ref` | Who asked, who approved, which change |
| `subject.correlation_id` | Ties all records from one reconcile together |
| `details` | Non-secret parameters (key IDs, fields changed, owner IDs) |

Mutations are logged as `attempted` before the call and `succeeded`/`failed`
after, so intent is recorded even if the process dies mid-call. Secret values
never appear: they are held in `SecretString` (redacted `Debug`, zeroized on drop).

Actions recorded: `policy_check`, `approval_check`, `create_application`,
`update_application`, `drift_detected`, `create_service_principal`,
`add_owner`, `remove_owner`, `add_password`, `deliver_secret`,
`remove_password`, `delete_application`, `retain_application`, `cleanup`.

## Control mapping

| Control objective | Mechanism | Evidence an auditor can pull | SOX ITGC area | NIST SP 800-53 | OSFI B-13 domain |
|---|---|---|---|---|---|
| Changes are authorised before implementation | Approval stamp verified against spec hash; VAP restricts writers to GitOps | PR approvals, `approval_check` records, `status.changeRef` | Change management | CM-3, CM-5 | Technology operations (change management) |
| Separation of duties | Requester must differ from approver; controller cannot approve | Annotations and audit `subject` fields | Change management | AC-5 | Governance |
| Least privilege for automation | `Application.ReadWrite.OwnedBy`; owner set limited to spec + controller | Entra app role assignment for controller SP | Logical access | AC-6 | Cyber security (identity and access) |
| No standing credentials for automation | Workload identity federation; client-secret auth disabled unless `ALLOW_CLIENT_SECRET_AUTH=true` | Deployment manifest, absence of secrets on controller SP | Logical access | IA-5 | Cyber security |
| Credential lifecycle | Max lifetime policy, rotation at one-third remaining, grace window, revoke stale and unknown secrets | `add_password` / `remove_password` records, Entra keyCredential dates | Logical access | IA-5(1), AC-2 | Cyber security |
| Accountability for every app | At least one human owner required; owners reconciled | `add_owner` / `remove_owner` records, Entra owners list | Logical access | AC-2 | Governance |
| Configuration integrity | Drift detection on name, audience, group claims, redirect URIs, owners, secrets | `drift_detected` records | Change management | CM-3, CM-6, SI-7 | Technology operations |
| Secure redirect configuration | HTTPS only, allowed domain list, no wildcards, no loopback in prod | `policy_check` denials | Change management | SC-23, CM-7 | Cyber security |
| Audit logging content and protection | Structured records, hash chain, SIEM with immutable retention | SIEM query by `subject.uid` or `change_ref` | IT operations | AU-2, AU-3, AU-9, AU-12 | Cyber security (logging and monitoring) |
| Deprovisioning | `deletionPolicy: Retain` (default) revokes all secrets and keeps the app as evidence; `Delete` soft-deletes | `remove_password` / `delete_application` records | Logical access | AC-2(3) | Cyber security |
| Software supply chain integrity | cargo-deny (advisories, licences, sources), SBOM (CycloneDX + BuildKit), cosign keyless signature, SLSA provenance, digest-pinned image | CI run, Rekor entry, attestation | Change management (SDLC) | SR-4, SR-11, SI-7, SA-15 | Technology operations (SDLC) |

## Open items before production

- **Leader election and HA.** Run one active replica with leader election so a
  failover never produces two writers. Required for a tier-0 dependency.
- **OpenBao sink.** Deliver secrets to OpenBao (KV v2, versioned, with its own
  audit device) instead of a Kubernetes Secret; split the Dex and Entra secrets.
  Until then, enable KMS encryption at rest and restrict Secret read RBAC.
- **Approval stamping job.** The merge pipeline step that writes the approval
  annotations must itself be a controlled, reviewed component.
- **Entra log reconciliation.** A scheduled job comparing Entra directory audit
  logs for the controller's SP against the controller's audit stream.
- **Egress restriction.** Allow only `login.microsoftonline.com`,
  `graph.microsoft.com` and the API server (FQDN-aware egress or proxy).
- **Group assignment.** Needs `AppRoleAssignment.ReadWrite.All`, a privileged
  permission IAM should approve separately; not implemented.
- **Retention periods.** Confirm audit log retention with Records Management.
- **Threat model and penetration test** before onboarding production teams.
- **Integration tests** against a non-production tenant, including drift and
  rotation crash-recovery scenarios.
