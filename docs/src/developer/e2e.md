# End-to-end testing

Charter's Graph behaviour (eventual consistency, throttling, permission edge
cases) only shows up against a real tenant, so the end-to-end tests run the
controller against a **non-production** Entra tenant and a local cluster.

## Setup

1. A development tenant and a controller app registration with a client
   secret in `~/.config/charter/dev.env`: see
   [bootstrap the Entra identity](../getting-started/entra-bootstrap.md).
2. A kind cluster with the CRD:
   ```sh
   kind create cluster --name charter-e2e
   kubectl apply -f deploy/crd.yaml
   kubectl create namespace team-e2e
   ```
3. For OpenBao delivery, External Secrets and OpenBao in dev mode:
   ```sh
   helm repo add external-secrets https://charts.external-secrets.io
   helm repo add openbao https://openbao.github.io/openbao-helm
   helm upgrade --install external-secrets external-secrets/external-secrets \
     -n external-secrets --create-namespace --wait
   helm upgrade --install openbao openbao/openbao -n openbao --create-namespace \
     --set server.dev.enabled=true --set server.dev.devRootToken=root \
     --set injector.enabled=false --wait
   kubectl -n external-secrets create secret generic openbao-token --from-literal=token=root
   ```
   and a `ClusterSecretStore` named `openbao` pointing at
   `http://openbao.openbao.svc:8200`, KV v2 mount `secret` (see
   [delivering to OpenBao](../guides/openbao.md#2-create-a-clustersecretstore)).
4. Run the controller with short timings so rotation behaviour is visible:
   ```sh
   set -a; . ~/.config/charter/dev.env; set +a
   ALLOWED_REDIRECT_DOMAINS=.e2e.example.com \
   ALLOWED_PUSH_SECRET_STORES=openbao DEFAULT_PUSH_SECRET_STORE=openbao \
   ROTATION_GRACE_HOURS=0 RUST_LOG=info,charter_iam=debug \
     cargo run
   ```
   `ROTATION_GRACE_HOURS=0` makes the push-sync check the only thing holding
   back revocation, which is what the rotation scenarios test.

## Scenarios

Each scenario lists what to do and what must be true afterwards. Read the
audit trail from the controller log, and Entra state with `az rest` against
`/applications(uniqueName='charter-team-e2e-<name>')`.

| # | Scenario | Do | Expect |
|---|---|---|---|
| 1 | Create | Apply a client with approval annotations | `Ready=True`; app, SP, owners (you + controller), one password matching the Secret's `key-id`; the delivered secret can get a token |
| 2 | Drift | Rename the app, add a redirect URI and a password via Graph; wait 30 seconds; poke | `drift_detected`, `update_application`, `remove_password` (`unknown_credential`); Entra back to spec |
| 3 | Approval gate | Change `secretRotation` without a new change-ref | `approval_check` `denied`, `PendingApproval`; nothing changes in Entra |
| 4 | Approval | Set a new change-ref | Applied; `status.changeRef` updated |
| 5 | Forced rotation | Remove `client-secret` from the Secret | One `add_password`, `deliver_secret`; previous key kept (grace) |
| 6 | Grace expiry | Restart with `ROTATION_GRACE_HOURS=0` | Previous key removed (`rotated_out`) |
| 7 | Lifetime shortened | Approve a shorter `secretRotation` | One `add_password` (`lifetime_shortened`); a "waiting for replication" log line instead of a second password; old key revoked |
| 8 | Push | Client with `pushSecret: {}` | `apply_push_secret`; `SecretPushed=True`; every key in OpenBao equals the Secret |
| 9 | Push gating | Forced rotation with push | Old key kept until `refreshTime` passes the rotation, then revoked; OpenBao has the new secret |
| 10 | Store not allowed | `pushSecret.clusterSecretStore: other` with a new change-ref | `PolicyViolation`; existing `PushSecret` untouched |
| 11 | Push removed | Remove `pushSecret` with a new change-ref | `delete_push_secret`; OpenBao path and metadata gone |
| 12 | Delete, Retain | Delete a client | Passwords revoked, `retain_application`, app still present |
| 13 | Delete, Delete | Delete a client with `deletionPolicy: Delete` and `pushSecret` | `delete_push_secret`, `delete_application`, OpenBao path gone |

Compare OpenBao with the Secret without printing values, for example by
hashing both sides or comparing in a script that prints only `match=True/False`.

## Expected noise

Replication lag produces occasional `failed` records that converge on retry;
see [troubleshooting](../guides/troubleshooting.md#replication-lag). A
scenario fails if state does not converge within a few minutes, not because a
transient `failed` record appeared.

## Cleaning up

Retained apps stay in the tenant: delete them in the Entra admin center. Apps
deleted with `Delete` sit in **Deleted applications** for 30 days and block
reuse of the same namespace and name until then; use fresh names per run.
