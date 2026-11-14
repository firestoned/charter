//! External Secrets Operator `PushSecret`: copies the delivered Kubernetes
//! Secret to OpenBao (or any `ClusterSecretStore` on the allow-list).
//!
//! The controller does not talk to OpenBao itself. It renders a `PushSecret`
//! owned by the IAMClient and reads back whether ESO has synced it, so a
//! rotated-out Entra secret is only revoked once OpenBao holds the new one.

use chrono::{DateTime, Utc};
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const GROUP: &str = "external-secrets.io";
pub const VERSION: &str = "v1alpha1";
pub const KIND: &str = "PushSecret";
pub const PLURAL: &str = "pushsecrets";
/// Hash of the rendered spec, so an unchanged PushSecret is not re-applied (and re-audited).
pub const ANN_SPEC_HASH: &str = "iam.rbc.example/push-spec-hash";

pub fn api_resource() -> ApiResource {
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(GROUP, VERSION, KIND), PLURAL)
}

/// `PushSecret.spec`: every key of `secret_name` becomes a property of one
/// OpenBao secret at `remote_key`. `deletionPolicy: Delete` removes the
/// OpenBao copy when the PushSecret goes away (IAMClient deleted, or
/// `spec.pushSecret` removed), so revoked credentials do not linger there.
pub fn spec(
    store: &str,
    secret_name: &str,
    remote_key: &str,
    keys: &[String],
    refresh: &str,
) -> Value {
    let data: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({
                "match": {
                    "secretKey": k,
                    "remoteRef": { "remoteKey": remote_key, "property": k },
                }
            })
        })
        .collect();
    json!({
        "refreshInterval": refresh,
        "deletionPolicy": "Delete",
        "secretStoreRefs": [{ "kind": "ClusterSecretStore", "name": store }],
        "selector": { "secret": { "name": secret_name } },
        "data": data,
    })
}

pub fn spec_hash(spec: &Value) -> String {
    hex::encode(Sha256::digest(spec.to_string().as_bytes()))
}

/// Has ESO pushed the Secret as it was at `since` (the last rotation)?
/// True when the PushSecret is Ready and its last refresh is not older than `since`.
pub fn synced_since(obj: &DynamicObject, since: DateTime<Utc>) -> SyncState {
    let status = obj.data.get("status");
    let ready = status
        .and_then(|s| s.get("conditions"))
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
        });
    let Some(ready) = ready else {
        return SyncState::Pending("PushSecret has not reported a Ready condition yet".into());
    };
    if ready.get("status").and_then(Value::as_str) != Some("True") {
        let msg = ready
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("not ready");
        return SyncState::Failed(msg.chars().take(500).collect());
    }
    let refreshed = status
        .and_then(|s| s.get("refreshTime"))
        .and_then(Value::as_str)
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc));
    match refreshed {
        // refreshTime has second precision; allow for the truncation.
        Some(t) if t + chrono::Duration::seconds(1) >= since => SyncState::Synced,
        _ => SyncState::Pending("waiting for a push after the last rotation".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    Synced,
    Pending(String),
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(status: Value) -> DynamicObject {
        let mut o = DynamicObject::new("x", &api_resource());
        o.data = json!({ "status": status });
        o
    }

    #[test]
    fn renders_one_entry_per_key() {
        let s = spec(
            "openbao",
            "portal-entra",
            "charter/team/portal",
            &["client-id".into(), "client-secret".into()],
            "1m",
        );
        assert_eq!(s["secretStoreRefs"][0]["kind"], "ClusterSecretStore");
        assert_eq!(s["selector"]["secret"]["name"], "portal-entra");
        assert_eq!(s["deletionPolicy"], "Delete");
        let d = s["data"].as_array().unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[1]["match"]["secretKey"], "client-secret");
        assert_eq!(
            d[1]["match"]["remoteRef"]["remoteKey"],
            "charter/team/portal"
        );
        assert_eq!(d[1]["match"]["remoteRef"]["property"], "client-secret");
    }

    #[test]
    fn sync_state() {
        let rotated = DateTime::parse_from_rfc3339("2026-11-14T10:00:00.500Z")
            .unwrap()
            .with_timezone(&Utc);
        let ready = |t: &str| {
            obj(json!({
                "conditions": [{ "type": "Ready", "status": "True" }],
                "refreshTime": t,
            }))
        };
        assert_eq!(
            synced_since(&ready("2026-11-14T10:00:30Z"), rotated),
            SyncState::Synced
        );
        // Same second as the rotation: second-precision truncation is tolerated.
        assert_eq!(
            synced_since(&ready("2026-11-14T10:00:00Z"), rotated),
            SyncState::Synced
        );
        assert!(matches!(
            synced_since(&ready("2026-11-14T09:59:00Z"), rotated),
            SyncState::Pending(_)
        ));
        assert!(matches!(
            synced_since(&obj(json!({})), rotated),
            SyncState::Pending(_)
        ));
        let failed = obj(json!({
            "conditions": [{ "type": "Ready", "status": "False", "message": "permission denied" }],
        }));
        assert_eq!(
            synced_since(&failed, rotated),
            SyncState::Failed("permission denied".into())
        );
    }
}
