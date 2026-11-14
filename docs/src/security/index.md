# Security and compliance

Charter manages identities for a regulated environment, so its own security
model is part of the product.

## Principles

1. **Fail closed.** No change reaches Entra unless the policy check and the
   approval check both pass. Missing configuration means "deny": an empty
   redirect domain list refuses every redirect URI, an empty push store list
   refuses every push, and approval is required unless explicitly disabled.
2. **Every change has a person, a reviewer and a ticket.** Requester and
   approver are recorded on the object and in every audit record, and must differ.
3. **Every change is evidenced twice.** In the controller's own audit log and
   in Entra's directory audit log for the controller's service principal.
4. **Least privilege, no standing secrets.** Graph `Application.ReadWrite.OwnedBy`
   only; workload identity federation instead of a client secret.
5. **Intent lives in Kubernetes; Entra is converged to it.** Out-of-band
   changes are detected, audited and reverted.
6. **Admins create, owners maintain.** Creation, deletion and admin-only
   fields need a platform admin and a change reference; owners may change
   their redirect URIs, within policy.

## Controls at a glance

| Area | Control |
|---|---|
| Controller identity | Workload identity federation; client-secret auth refused unless `ALLOW_CLIENT_SECRET_AUTH=true` |
| Graph permission | `Application.ReadWrite.OwnedBy` only: cannot touch apps it did not create |
| Authorisation | Admission policy plus the controller's approval gate (defence in depth) |
| Redirect URIs | HTTPS, allow-listed domains, no wildcards, no loopback by default |
| Secrets in memory | `SecretString`: redacted in debug output, zeroized on drop; never logged |
| Secret delivery | Written only to the client's namespace and to a controller-chosen OpenBao path in an allow-listed store |
| Credential lifetime | Capped by policy; automatic rotation; previous secret revoked after a grace window; unknown secrets revoked |
| Configuration integrity | Drift detection and reversion |
| Audit | JSON records before and after every mutation, hash-chained, shipped to immutable storage |
| Transport | Graph and token endpoints over HTTPS only (`https_only` client), 30-second timeouts |
| Supply chain | `cargo-deny` (advisories, licences, sources), CycloneDX SBOM, keyless cosign signature, SLSA provenance, distroless non-root image |
| Runtime | Non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp |

## Pages

- [Threat model](threat-model.md): assets, trust boundaries, threats and mitigations.
- [Compliance and control mapping](compliance.md): control objectives mapped to
  SOX ITGC, NIST SP 800-53 and OSFI B-13, and the open items before production.

## Reporting a vulnerability

Report security issues privately to the maintainers through GitHub's private
vulnerability reporting on [firestoned/charter](https://github.com/firestoned/charter/security),
not in a public issue.
