# Consuming the credentials

## From the Kubernetes Secret

Every client gets a Secret named `<name>-entra` in its namespace:

| Key | Use as |
|---|---|
| `tenant-id` | Tenant ID |
| `client-id` | OAuth client ID |
| `client-secret` | OAuth client secret |
| `issuer` | OIDC issuer, `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `dex-client-secret`, `dex-config.yaml` | Only with `spec.dex`; see [Dex](../concepts/dex.md) |

As environment variables:

```yaml
env:
  - name: OIDC_ISSUER
    valueFrom: { secretKeyRef: { name: payments-portal-entra, key: issuer } }
  - name: OIDC_CLIENT_ID
    valueFrom: { secretKeyRef: { name: payments-portal-entra, key: client-id } }
  - name: OIDC_CLIENT_SECRET
    valueFrom: { secretKeyRef: { name: payments-portal-entra, key: client-secret } }
```

As a mounted volume (preferred, because it updates in place on rotation):

```yaml
volumes:
  - name: oidc
    secret: { secretName: payments-portal-entra }
containers:
  - name: app
    volumeMounts:
      - { name: oidc, mountPath: /var/run/secrets/oidc, readOnly: true }
```

## From OpenBao

With `spec.pushSecret`, the same keys are stored as one KV v2 secret at
`<prefix><namespace>/<name>`, by default `charter/team-payments/payments-portal`
under the store's mount. `status.pushedTo` shows the exact store and path:

```sh
kubectl -n team-payments get iamc payments-portal -o jsonpath='{.status.pushedTo}'
# openbao:charter/team-payments/payments-portal

bao kv get -field=client-secret secret/charter/team-payments/payments-portal
```

Grant the consuming workload read access to that path only.

## Handling rotation

The secret changes when it rotates (at two thirds of its lifetime by
default). The previous secret keeps working for the grace window
(`ROTATION_GRACE_HOURS`, default 24 hours), so a consumer must pick up the new
value within that time.

| How you consume it | What to do |
|---|---|
| Mounted Secret volume | Re-read the file on each token request, or on change. The kubelet updates it within about a minute. |
| Environment variables | Restart on change: for example a reloader that rolls the Deployment when the Secret changes. |
| OpenBao | Re-read on a schedule shorter than the grace window, or use a lease-aware agent. Charter only revokes the old secret after OpenBao has the new one. |
| `subPath` mount | Avoid: `subPath` mounts never update. |

To see when the next rotation will happen:

```sh
kubectl -n team-payments get iamc payments-portal -o jsonpath='{.status.secretExpiresAt}'
```

Rotation starts when a third of the lifetime is left, so for `90d` it happens
about 30 days before that date.

## Who can read the Secret

Charter writes the Secret into the client's namespace and does not change who
can read it. Restrict `get` on Secrets in that namespace to the consuming
workloads, and enable KMS encryption at rest for Secrets cluster-wide.
