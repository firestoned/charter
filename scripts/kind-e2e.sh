#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, charter
# SPDX-License-Identifier: Apache-2.0
#
# Kind end-to-end checks that need no cloud credentials (`make kind-e2e`):
#
#   1. the CRD installs and the example IAMClient validates against it;
#   2. the admission policies (deploy/admission-policy.yaml) enforce "admins
#      create, owners maintain" against a real API server, by impersonating the
#      Flux provisioner, a platform admin, an owner and an outsider;
#   3. the controller image starts in-cluster with the shipped RBAC and
#      Deployment and fails closed without workload identity.
#
# The live Entra scenarios (docs/src/developer/e2e.md) need a tenant and run by
# hand. Usage: kind-e2e.sh <kubeconfig> <controller image>
set -euo pipefail
# Checks are often fed by a pipe (`client x | expect_allowed ...`): run the last
# command of a pipeline in this shell so their pass/fail counts are kept.
shopt -s lastpipe

KUBECONFIG=${1:?kubeconfig}
IMAGE=${2:?controller image}
export KUBECONFIG

NS=team-e2e
PROVISIONER=system:serviceaccount:charter-system:charter-provisioner
ADMIN_GROUP=00000000-0000-0000-0000-00000000ad01   # adminGroups in the shipped ConfigMap
OWNER_GROUP=team-e2e-owners
OK_HOST=portal.apps.example.rbc.com                 # allowedRedirectDomains in the shipped ConfigMap

pass=0
fail=0
ok() { echo "  ✓ $*"; pass=$((pass + 1)); }
bad() { echo "  ✗ $*"; fail=$((fail + 1)); }

as_provisioner() { kubectl --as="$PROVISIONER" "$@"; }
as_admin() { kubectl --as=alice@example.com --as-group="$ADMIN_GROUP" --as-group=system:authenticated "$@"; }
as_owner() { kubectl --as=olive@example.com --as-group="$OWNER_GROUP" --as-group=system:authenticated "$@"; }
as_outsider() { kubectl --as=mallory@example.com --as-group=system:authenticated "$@"; }
# Has RBAC to create IAMClients but is not a platform admin: only the policy stops it.
as_nonadmin() { kubectl --as=nadia@example.com --as-group=system:authenticated "$@"; }

# expect_allowed <description> <command...>
expect_allowed() {
  local what=$1; shift
  local out
  if out=$("$@" 2>&1); then ok "$what"; else bad "$what: $out"; fi
}

# expect_denied <description> <message fragment> <command...>
expect_denied() {
  local what=$1 frag=$2; shift 2
  local out
  if out=$("$@" 2>&1); then
    bad "$what: was allowed"
  elif grep -q -- "$frag" <<<"$out"; then
    ok "$what"
  else
    bad "$what: denied for another reason: $out"
  fi
}

# expect_eq <description> <actual> <expected>
expect_eq() {
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got '$2', expected '$3'"; fi
}

annotation() {
  kubectl -n "$NS" get iamc "$1" -o "jsonpath={.metadata.annotations.iam\.rbc\.example/$2}"
}

client() {
  cat <<YAML
apiVersion: iam.rbc.example/v1alpha1
kind: IAMClient
metadata:
  name: $1
  namespace: $NS
  annotations:
    iam.rbc.example/requested-by: requester@example.com
    iam.rbc.example/approved-by: approver@example.com
    iam.rbc.example/change-ref: CHG-E2E-0001
spec:
  displayName: E2E $1
  redirectURIs: [https://$OK_HOST/callback]
  owners: [11111111-1111-1111-1111-111111111111]
YAML
}

echo "== 1. CRD"
kubectl apply -f deploy/crd.yaml >/dev/null
kubectl wait --for=condition=Established crd/iamclients.iam.rbc.example --timeout=60s >/dev/null
ok "CRD established"
for ns in "$NS" charter-system; do
  kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns" >/dev/null
done
# RBAC the policies sit on top of: provisioner and admins may do anything to
# IAMClients; the owner group gets the per-client Role the ResourceSet renders.
kubectl apply -f - >/dev/null <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: charter-e2e-iamclient-admin }
rules:
  - apiGroups: ["iam.rbc.example"]
    resources: ["iamclients"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: charter-e2e-iamclient-admin }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: charter-e2e-iamclient-admin }
subjects:
  - { kind: ServiceAccount, name: charter-provisioner, namespace: charter-system }
  - { apiGroup: rbac.authorization.k8s.io, kind: Group, name: "$ADMIN_GROUP" }
  - { apiGroup: rbac.authorization.k8s.io, kind: User, name: nadia@example.com }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: iamclient-e2e-portal-owner, namespace: $NS }
rules:
  - apiGroups: ["iam.rbc.example"]
    resources: ["iamclients"]
    resourceNames: ["e2e-portal"]
    verbs: ["get", "patch", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: iamclient-e2e-portal-owner, namespace: $NS }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: iamclient-e2e-portal-owner }
subjects:
  - { apiGroup: rbac.authorization.k8s.io, kind: Group, name: "$OWNER_GROUP" }
YAML
# The owner Role above also grants delete, so a denied delete proves the
# policy (not RBAC) refused it.

# As an admin, so the check also passes on a re-run with the policies installed.
sed "s/namespace: team-payments/namespace: $NS/" deploy/example-iamclient.yaml |
  expect_allowed "example IAMClient validates (server-side dry run)" as_admin create --dry-run=server -f -

echo "== 2. Admission policies"
kubectl apply -f deploy/admission-policy.yaml >/dev/null

# The policies are enforced a moment after they are stored: wait until a
# non-admin's create is refused by the validating policy and an admin's create
# comes back stamped by the mutating one (server-side dry runs; nothing is created).
settled=""
for _ in $(seq 1 90); do
  denied=$(client probe | as_nonadmin create --dry-run=server -f - 2>&1 || true)
  stamped=$(client probe | as_admin create --dry-run=server -f - \
    -o jsonpath='{.metadata.annotations.iam\.rbc\.example/last-modified-by}' 2>/dev/null || true)
  if grep -q "only platform admins can create" <<<"$denied" && [ "$stamped" = "alice@example.com" ]; then
    settled=yes
    break
  fi
  sleep 1
done
[ -n "$settled" ] || { echo "ERROR: admission policies not enforced after 90s: $denied / stamped='$stamped'"; exit 1; }
ok "policies enforced"

client e2e-portal | expect_allowed "provisioner creates a client" as_provisioner create -f -
expect_eq "author stamped on create" "$(annotation e2e-portal last-modified-by)" "$PROVISIONER"

client e2e-other | expect_denied "non-admin with create RBAC cannot create a client" "only platform admins can create" as_nonadmin create -f -
client e2e-other | expect_denied "outsider cannot create a client (RBAC)" "forbidden" as_outsider create -f -

expect_allowed "owner changes redirectURIs on an allowed domain" \
  as_owner -n "$NS" patch iamc e2e-portal --type merge \
  -p "{\"spec\":{\"redirectURIs\":[\"https://$OK_HOST/callback\",\"https://staging.apps.example.rbc.com/callback\"]}}"
expect_eq "author stamped on owner update" "$(annotation e2e-portal last-modified-by)" "olive@example.com"

expect_allowed "owner's hand-set last-modified-by is accepted but overwritten" \
  as_owner -n "$NS" annotate iamc e2e-portal --overwrite iam.rbc.example/last-modified-by=someone-else
expect_eq "forged last-modified-by replaced by the real author" "$(annotation e2e-portal last-modified-by)" "olive@example.com"

for field in '"displayName":"Renamed"' '"owners":["22222222-2222-2222-2222-222222222222"]' \
  '"groups":["G"]' '"secretRotation":"720d"' '"deletionPolicy":"Delete"' \
  '"dex":{"issuerURL":"https://dex.apps.example.rbc.com"}' '"pushSecret":{}'; do
  expect_denied "owner cannot change ${field%%:*}" "owners may only change spec.redirectURIs" \
    as_owner -n "$NS" patch iamc e2e-portal --type merge -p "{\"spec\":{$field}}"
done

expect_denied "owner cannot change the change-ref" "approval annotations can only be set by platform admins" \
  as_owner -n "$NS" annotate iamc e2e-portal --overwrite iam.rbc.example/change-ref=CHG-FORGED
expect_denied "owner cannot set approved-by" "approval annotations can only be set by platform admins" \
  as_owner -n "$NS" annotate iamc e2e-portal --overwrite iam.rbc.example/approved-by=olive@example.com

for uri in "http://$OK_HOST/callback" "https://*.apps.example.rbc.com/callback" \
  "https://evil.example.net/callback" "https://apps.example.rbc.com.evil.net/callback"; do
  expect_denied "redirect URI refused: $uri" "redirect URIs must be https" \
    as_owner -n "$NS" patch iamc e2e-portal --type merge -p "{\"spec\":{\"redirectURIs\":[\"$uri\"]}}"
done

expect_denied "owner cannot delete the client" "only platform admins can delete" \
  as_owner -n "$NS" delete iamc e2e-portal --wait=false

expect_allowed "admin changes an admin-only field" \
  as_admin -n "$NS" patch iamc e2e-portal --type merge -p '{"spec":{"displayName":"Renamed by admin"}}'
expect_allowed "admin sets a new change-ref" \
  as_admin -n "$NS" annotate iamc e2e-portal --overwrite iam.rbc.example/change-ref=CHG-E2E-0002
expect_allowed "admin deletes the client" as_admin -n "$NS" delete iamc e2e-portal --wait=false

echo "== 3. Controller image"
kubectl apply -f deploy/rbac.yaml >/dev/null
sed -e "s#image: .*#image: $IMAGE#" deploy/deployment.yaml |
  sed -e 's#azure.workload.identity/use: "true"#azure.workload.identity/use: "false"#' |
  kubectl apply -f - >/dev/null
kubectl -n charter-system set env deploy/charter-iam \
  AZURE_TENANT_ID=00000000-0000-0000-0000-000000000001 \
  AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000002 >/dev/null
kubectl -n charter-system patch deploy charter-iam --type json \
  -p '[{"op":"add","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]' >/dev/null
logs=""
for _ in $(seq 1 90); do
  logs=$(kubectl -n charter-system logs deploy/charter-iam --all-containers 2>/dev/null || true)
  grep -q "workload identity required" <<<"$logs" && break
  sleep 2
done
if grep -q "workload identity required: AZURE_FEDERATED_TOKEN_FILE is not set" <<<"$logs"; then
  ok "image starts as non-root with the shipped Deployment and fails closed without workload identity"
else
  bad "controller did not fail closed as expected; logs: $logs"
  kubectl -n charter-system describe pods -l app=charter-iam | tail -30
fi

echo
echo "kind e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
