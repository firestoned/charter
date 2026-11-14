# Microsoft Graph usage

Charter calls Microsoft Graph v1.0 (`https://graph.microsoft.com/v1.0`) with
an app-only token for the scope `https://graph.microsoft.com/.default`. The
only permission granted is `Application.ReadWrite.OwnedBy`.

## Token acquisition

`POST <AZURE_AUTHORITY_HOST>/<tenant>/oauth2/v2.0/token` with
`grant_type=client_credentials` and either:

- `client_assertion` set to the projected service account token
  (`AZURE_FEDERATED_TOKEN_FILE`, re-read on every request) with
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, or
- `client_secret` (development only).

The token is cached until 5 minutes before it expires. The controller's own
service principal object ID is read from the token's `oid` claim, so no
directory read permission is needed to find itself.

## Calls

| Purpose | Request |
|---|---|
| Read app | `GET /applications(uniqueName='<u>')?$select=id,appId,displayName,signInAudience,groupMembershipClaims,web,passwordCredentials` |
| Create or update app | `PATCH /applications(uniqueName='<u>')` with `Prefer: create-if-missing` |
| Delete app | `DELETE /applications(uniqueName='<u>')` |
| Read service principal | `GET /servicePrincipals(appId='<appId>')?$select=id` |
| Create service principal | `POST /servicePrincipals` `{"appId": "<appId>"}` |
| List owners | `GET /applications/<id>/owners?$select=id` |
| Add owner | `POST /applications/<id>/owners/$ref` |
| Remove owner | `DELETE /applications/<id>/owners/<ownerId>/$ref` |
| Add password | `POST /applications/<id>/addPassword` |
| Remove password | `POST /applications/<id>/removePassword` `{"keyId": "<keyId>"}` |

`404` on delete, remove-owner and remove-password is treated as success.
Values placed in OData keys are escaped (single quotes doubled).

## Why `Application.ReadWrite.OwnedBy` is enough

| Operation | Allowed because |
|---|---|
| Create an app | The permission allows creating apps; the caller becomes an owner |
| Read, update, delete it | The caller owns it |
| Create its service principal | The app is owned by the caller and is in the local tenant |
| Add and remove owners, including users | The caller owns the app (verified against a real tenant) |
| Add and remove passwords | The caller owns the app |

The controller keeps itself in every app's owner list and never removes
itself. If a person removes it in the portal, the controller loses access to
that app; restore it as an owner to resume management.

## Limits and behaviour

- **Eventual consistency.** Reads can lag writes by seconds. See
  [replication lag](../guides/troubleshooting.md#replication-lag).
- **Throttling.** Graph returns `429` under load; the controller retries after
  30 seconds.
- **Soft delete.** Deleted apps stay in **Deleted applications** for 30 days
  and keep their `uniqueName`.
