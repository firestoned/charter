# Quickstart: local cluster and dev tenant

Run the controller from source against a kind cluster and a non-production
Entra tenant, create a client, and watch it converge. Takes about ten minutes
once [the Entra identity is bootstrapped](entra-bootstrap.md) with a client
secret in `~/.config/charter/dev.env`.

## 1. Create a cluster and install the CRD

```sh
kind create cluster --name charter
kubectl apply -f deploy/crd.yaml
kubectl wait --for=condition=Established crd/iamclients.iam.rbc.example
kubectl create namespace team-demo
```

## 2. Run the controller

```sh
set -a; . ~/.config/charter/dev.env; set +a
export ALLOWED_REDIRECT_DOMAINS=.demo.example.com
cargo run
```

The controller logs JSON. The first lines confirm the policy it loaded:

```json
{"level":"WARN","fields":{"message":"client secret auth enabled; this is for local development only"}}
{"level":"INFO","fields":{"message":"starting charter-iam","policy":"Policy { name_prefix: \"charter-\", allowed_redirect_domains: [\".demo.example.com\"], ... require_approval: true }"}}
```

!!! note "Redirect domains do not have to resolve"
    Entra does not check that a redirect host exists, so a made-up domain is
    fine for a trial. It must still match `ALLOWED_REDIRECT_DOMAINS` and use HTTPS.

## 3. Create a client

Approval is required by default, so set a requester, a different approver and
a change reference:

```yaml title="demo.yaml"
apiVersion: iam.rbc.example/v1alpha1
kind: IAMClient
metadata:
  name: demo-portal
  namespace: team-demo
  annotations:
    iam.rbc.example/requested-by: requester@example.com
    iam.rbc.example/approved-by: approver@example.com
    iam.rbc.example/change-ref: CHG-DEMO-0001
spec:
  displayName: Demo Portal
  redirectURIs: [https://portal.demo.example.com/callback]
  owners: [<your-object-id>]
  secretRotation: 90d
```

```sh
kubectl apply -f demo.yaml
kubectl -n team-demo get iamc -w
```

Within a few seconds:

```text
NAME          APPID                                  READY   SECRETEXPIRES
demo-portal   3f2a9c1e-5b7d-4e8a-9c0f-1d2e3f4a5b6c   True    2027-02-12T14:39:52Z
```

The first reconcile can fail once with a `403` or `400` while Entra replicates
the new app; the controller retries after 30 seconds. See
[troubleshooting](../guides/troubleshooting.md#replication-lag).

## 4. Look at what was created

```sh
kubectl -n team-demo get secret demo-portal-entra -o jsonpath='{.data}' | jq 'keys'
# ["client-id", "client-secret", "issuer", "tenant-id"]

kubectl -n team-demo describe iamc demo-portal     # Events mirror the audit trail
```

In the Entra admin center, under **App registrations > All applications**,
search for `charter-`. The registration `charter-Demo Portal` has:

- `uniqueName` `charter-team-demo-demo-portal`,
- your user and `charter-iam` as owners,
- one client secret whose key ID matches the Secret's
  `iam.rbc.example/key-id` annotation,
- the redirect URI from the spec.

## 5. Try drift correction

Rename the app or add a redirect URI in the portal, then trigger a reconcile
(the controller also checks every hour):

```sh
kubectl -n team-demo label iamc demo-portal poke=$(date +%s) --overwrite
```

The controller logs `drift_detected` and `update_application`, and the portal
shows the approved values again. If you poke within a few seconds of the
portal edit, Graph may not show the edit yet; poke again.

## 6. Clean up

```sh
kubectl -n team-demo delete iamc demo-portal
```

With the default `deletionPolicy: Retain`, all client secrets are revoked and
the registration is kept as evidence. Delete it in the portal if you no longer
want it. Then `kind delete cluster --name charter`.

## Next

- Add [OpenBao delivery](../guides/openbao.md) to the same cluster.
- Install the [admission policy](../reference/rbac.md#admission-policy) to see
  owner self-service enforced.
- Read [the reconcile loop](../concepts/reconcile-loop.md) to understand each
  audit record you just saw.
