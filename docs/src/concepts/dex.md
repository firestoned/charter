<!-- Copyright (c) 2026 Erick Bourgeois, charter -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dex in front of Entra

A team can put [Dex](https://dexidp.io/) between its application and Entra.
Entra then only knows about Dex; the application authenticates to Dex. This
gives the team one stable OIDC issuer, group filtering, and lets several
applications share one Entra registration's sign-in without each getting
Entra redirect URIs.

## Enabling it

```yaml
spec:
  displayName: Payments Portal
  redirectURIs: [https://payments.apps.example.com/callback]
  groups: [APP-Payments-Users, APP-Payments-Admins]
  dex:
    issuerURL: https://dex.team-payments.apps.example.com
```

`dex` is admin-only. `issuerURL` must pass the same rules as a redirect URI
(HTTPS, allowed domain).

## What changes

| Without `dex` | With `dex` |
|---|---|
| Entra redirect URIs are `spec.redirectURIs` | Entra's only redirect URI is `<issuerURL>/callback` |
| The app authenticates to Entra directly | The app authenticates to Dex; `spec.redirectURIs` become the Dex static client's redirect URIs |
| Secret keys: `tenant-id`, `client-id`, `client-secret`, `issuer` | Also `dex-client-secret` and `dex-config.yaml` |

## The generated configuration

`dex-config.yaml` is a fragment: a Microsoft connector (Dex to Entra) and a
static client (the app to Dex). A Dex config renderer merges fragments per
issuer.

```yaml
connectors:
  - type: microsoft
    id: entra
    name: Entra ID
    config:
      clientID: <client-id>
      clientSecret: <client-secret>
      redirectURI: https://dex.team-payments.apps.example.com/callback
      tenant: <tenant-id>
      groups: [APP-Payments-Users, APP-Payments-Admins]
      onlySecurityGroups: true
staticClients:
  - id: payments-portal              # the IAMClient name
    name: Payments Portal
    secret: <dex-client-secret>
    redirectURIs: [https://payments.apps.example.com/callback]
```

- The **Entra client secret** in the fragment rotates with the client's
  secret, so the fragment changes on every rotation; Dex must reload it.
- The **Dex client secret** is generated once (32 random bytes, URL-safe
  base64) and kept across reconciles. It is not rotated by Charter.
- `groups` makes Entra emit group claims for groups assigned to the app
  (`groupMembershipClaims: ApplicationGroup`) and Dex filter on them. Assigning
  groups to the app is not done by Charter.

Splitting the Dex and Entra secrets into separate Secrets is an
[open item](../security/compliance.md#open-items-before-production).
