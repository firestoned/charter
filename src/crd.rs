//! The `IAMClient` custom resource: what a team asks for.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A team's request for an Entra app registration, plus the OIDC wiring around it.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "iam.rbc.example",
    version = "v1alpha1",
    kind = "IAMClient",
    namespaced,
    status = "IAMClientStatus",
    shortname = "iamc",
    printcolumn = r#"{"name":"AppID","type":"string","jsonPath":".status.appId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"SecretExpires","type":"string","jsonPath":".status.secretExpiresAt"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IAMClientSpec {
    /// Human-readable name. Admin-only. The controller prefixes it with the platform naming prefix.
    pub display_name: String,

    /// Redirect URIs of the team's application. Owner-editable.
    /// With `dex` set, these become Dex static-client redirect URIs and Entra only
    /// ever sees Dex's own callback. Without `dex`, they go straight onto the Entra app.
    #[serde(rename = "redirectURIs", default)]
    pub redirect_uris: Vec<String>,

    /// Entra groups the app cares about. Emitted as the Dex connector `groups` filter,
    /// and switches Entra group claims to `ApplicationGroup`.
    #[serde(default)]
    pub groups: Vec<String>,

    /// How long each client secret lives, e.g. `90d` or `720h`. Rotation starts
    /// when a third of the lifetime remains.
    #[serde(default = "default_rotation")]
    pub secret_rotation: String,

    /// Entra object IDs of human owners to add to the registration.
    #[serde(default)]
    pub owners: Vec<String>,

    /// What happens in Entra when this IAMClient is deleted. `Retain` (default)
    /// revokes the client secrets but keeps the registration for audit and
    /// recovery; `Delete` removes it (Entra soft-deletes for 30 days).
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,

    /// Optional Dex front door for this client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dex: Option<DexSpec>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DexSpec {
    /// Issuer URL of the team's Dex, e.g. `https://dex.team-payments.apps.example.com`.
    /// Entra gets `<issuerURL>/callback` as its only redirect URI.
    #[serde(rename = "issuerURL")]
    pub issuer_url: String,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum DeletionPolicy {
    #[default]
    Retain,
    Delete,
}

fn default_rotation() -> String {
    "90d".into()
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IAMClientStatus {
    /// Application (client) ID of the Entra app registration.
    pub app_id: Option<String>,
    /// Directory object ID of the app registration.
    pub object_id: Option<String>,
    /// Object ID of the service principal in the tenant.
    pub service_principal_id: Option<String>,
    /// keyId of the client secret currently delivered.
    pub secret_key_id: Option<String>,
    /// RFC 3339 expiry of the current client secret.
    pub secret_expires_at: Option<String>,
    /// Kubernetes Secret holding the credentials and Dex config.
    pub secret_name: Option<String>,
    pub observed_generation: Option<i64>,
    /// Evidence of the approval the last applied spec was reconciled under.
    pub applied_spec_hash: Option<String>,
    /// Hash of the admin-only fields last applied; a mismatch needs a new approval.
    pub applied_admin_hash: Option<String>,
    pub approved_by: Option<String>,
    pub change_ref: Option<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Same shape as metav1.Condition, kept local so the schema derives cleanly.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
    pub observed_generation: Option<i64>,
}
