# Why Charter

## The problem

Every application that signs users in with Entra ID needs an app
registration. In most organisations these are created by hand in the portal,
or by a ticket to a central identity team. Both routes have the same
weaknesses:

- **Slow and manual.** A team waits days for a registration and a secret, and
  again for every redirect URI change.
- **Weak evidence.** The ticket says what was asked for; nothing proves the
  registration still looks like that six months later.
- **Secrets by email.** Client secrets are copied out of the portal and passed
  around, and they expire on dates nobody tracks, which causes outages.
- **No owner.** Registrations outlive the teams that asked for them.

## What Charter does about it

| Need | How Charter meets it |
|---|---|
| Self-service without losing control | Admins create a client once; the owning team then maintains its own redirect URIs through the Kubernetes API, within a domain policy. |
| Every change authorised | Creation and admin-only changes need a requester, a different approver and a change reference. The controller re-checks this before touching Entra. |
| Every change evidenced | Each Graph mutation is recorded as `attempted` before the call and `succeeded` or `failed` after it, as JSON and as a Kubernetes Event. |
| Configuration stays as approved | Hand edits in the portal (name, redirect URIs, group claims, owners, extra secrets) are detected and reverted, with a `drift_detected` record. |
| No secrets passed by hand | The client secret is delivered straight into a Kubernetes Secret, and optionally OpenBao. Nobody sees it. |
| No surprise expiry | Secrets rotate automatically when a third of their lifetime is left; the old one stays valid for a grace window. |
| Least privilege | The controller holds only `Application.ReadWrite.OwnedBy`, so it can only touch registrations it created. |
| No standing credential for the controller | It authenticates with workload identity federation; there is no secret to leak. |

## Prior art

Checked 2026-11-12.

| Option | Manages Entra apps? | Notes |
|---|---|---|
| Cluster API Azure (CAPZ) | No | Uses Entra and workload identity to provision clusters; no app-registration CRDs. |
| Azure Service Operator v2 | Yes, recently | `entra.azure.com` `Application` since v2.21.0, `ServicePrincipal` since v2.22.0, plus `SecurityGroup`. No federated credential or client secret resource. |
| Crossplane provider-azuread | Yes, broadest | Applications, service principals, federated identity credentials, passwords. Terraform-based (Upjet), so it carries a heavy runtime. |
| Charter | Yes, narrow | One opinionated resource that also does secret delivery, rotation, Dex config, approvals and auditing, which none of the above do. |

**Reuse.** If Azure Service Operator or Crossplane is already in place, Charter's
Graph module could be swapped for one that writes their `Application` and
`ServicePrincipal` objects, keeping the parts they lack: approvals, auditing,
rotation, secret delivery and Dex config. The reconcile shape stays the same.

## Non-goals

- **Not a general Entra management tool.** Charter manages web app
  registrations for sign-in, with single-tenant audience (`AzureADMyOrg`). It
  does not manage users, groups, conditional access or API permissions.
- **No group assignment yet.** Assigning groups to the app needs
  `AppRoleAssignment.ReadWrite.All`, a privileged permission that should be
  approved separately.
- **Not an identity provider.** Dex or Entra is the identity provider; Charter
  only wires them together.
