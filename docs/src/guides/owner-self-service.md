# Owners: editing redirect URIs

The owning team maintains its client's redirect URIs itself, through the
Kubernetes API. No ticket and no platform admin are needed.

## Adding or changing a redirect URI

```sh
kubectl -n team-payments edit iamc payments-portal
```

or, scripted:

```sh
kubectl -n team-payments patch iamc payments-portal --type merge -p '
spec:
  redirectURIs:
    - https://payments.apps.example.com/callback
    - https://payments-staging.apps.example.com/callback
'
```

Within seconds the Entra registration (or, with Dex, the Dex static client)
has the new list. The audit record carries your Kubernetes username in
`subject.last_modified_by`, stamped by admission.

## Rules

Every redirect URI must:

- be absolute and use `https`,
- have no `*` anywhere,
- have a host equal to, or under, one of the platform's allowed domains,
- not be `localhost` or `127.0.0.1` (unless the platform enabled loopback for development).

A URI that breaks a rule is rejected at admission with
"redirect URIs must be https, without wildcards, on an allowed domain". If it
gets past admission, the controller refuses it with `Ready=False`,
`PolicyViolation`, and changes nothing in Entra.

## What you cannot change

Every other field (`displayName`, `owners`, `groups`, `secretRotation`,
`deletionPolicy`, `dex`, `pushSecret`) and the approval annotations are
admin-only. Admission rejects the change with "owners may only change
spec.redirectURIs; other fields need a platform admin". Ask your platform
team; they change it with a new change reference.

## What you can read

```sh
kubectl -n team-payments get iamc payments-portal -o yaml   # spec and status
kubectl -n team-payments describe iamc payments-portal      # recent events
```

Reading the credentials Secret is governed by your namespace's own RBAC; see
[consuming the credentials](consuming-credentials.md).
