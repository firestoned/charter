# Bootstrap the Entra identity

The controller acts in Entra as its own app registration. Create it once per
tenant (or per environment), grant it `Application.ReadWrite.OwnedBy`, and give
it a way to authenticate.

## 1. Create the registration and its service principal

```sh
TENANT=<tenant-id>
az login --tenant "$TENANT" --allow-no-subscriptions

APP=$(az ad app create --display-name charter-iam --query appId -o tsv)
az ad sp create --id "$APP"
```

!!! tip "Finding your tenant ID"
    In the Entra admin center, **Identity > Overview** shows the Tenant ID.
    From the CLI: `az account tenant list -o table`.

## 2. Grant the Graph permission

```sh
GRAPH=00000003-0000-0000-c000-000000000000
OWNED_BY=18a4783c-866b-4cc7-a460-3d5e5662c884   # Application.ReadWrite.OwnedBy

az ad app permission add --id "$APP" --api "$GRAPH" --api-permissions "$OWNED_BY=Role"
az ad app permission admin-consent --id "$APP"
```

Admin consent can fail for a minute after the service principal is created,
while the directory replicates. Retry it.

Verify the grant by acquiring a token and reading its `roles` claim. It must
contain `Application.ReadWrite.OwnedBy` and nothing else.

## 3. Choose how the controller authenticates

=== "Production: workload identity federation"

    No secret exists. The cluster's service account token is exchanged for an
    Entra token. Add a federated credential that trusts the controller's
    service account:

    ```sh
    ISSUER=$(az aks show -g <resource-group> -n <cluster> --query oidcIssuerProfile.issuerUrl -o tsv)

    az ad app federated-credential create --id "$APP" --parameters "{
      \"name\": \"charter-iam\",
      \"issuer\": \"$ISSUER\",
      \"subject\": \"system:serviceaccount:charter-system:charter-iam\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }"
    ```

    Then put the client ID on the service account
    (`azure.workload.identity/client-id` in `deploy/rbac.yaml`). The Azure
    Workload Identity webhook injects `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
    `AZURE_FEDERATED_TOKEN_FILE` and `AZURE_AUTHORITY_HOST` into the pod. The
    controller re-reads the token file on every token request, because the
    kubelet rotates it.

    On a cluster other than AKS, the cluster's service account issuer must be
    publicly reachable for Entra to validate tokens.

=== "Development: client secret"

    Create a short-lived secret and write it to a private env file without
    printing it:

    ```sh
    umask 077; mkdir -p ~/.config/charter
    az ad app credential reset --id "$APP" --display-name charter-dev \
      --end-date "$(date -u -v+30d +%Y-%m-%d 2>/dev/null || date -u -d '+30 days' +%Y-%m-%d)" \
      --query password -o tsv |
      { read -r s; printf 'AZURE_TENANT_ID=%s\nAZURE_CLIENT_ID=%s\nAZURE_CLIENT_SECRET=%s\nALLOW_CLIENT_SECRET_AUTH=true\n' "$TENANT" "$APP" "$s"; } \
      > ~/.config/charter/dev.env
    ```

    The controller refuses to start with a client secret unless
    `ALLOW_CLIENT_SECRET_AUTH=true` is set, and logs a warning when it is.
    Never do this in production.

## 4. Find an owner

Every client needs at least one human owner, given as an Entra **object ID**.
For a test, use your own:

```sh
az ad signed-in-user show --query id -o tsv
```
