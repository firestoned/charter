// Copyright (c) 2026 Erick Bourgeois, charter
// SPDX-License-Identifier: Apache-2.0

//! Platform policy (set by Enterprise IAM via controller config) and the
//! approval gate checked before any Entra mutation.

use crate::crd::{IAMClient, IAMClientSpec};
use chrono::Duration;
use kube::ResourceExt;
use sha2::{Digest, Sha256};

pub const ANN_REQUESTED_BY: &str = "iam.rbc.example/requested-by";
pub const ANN_APPROVED_BY: &str = "iam.rbc.example/approved-by";
pub const ANN_CHANGE_REF: &str = "iam.rbc.example/change-ref";
/// Stamped by the MutatingAdmissionPolicy from request.userInfo; cannot be forged.
pub const ANN_LAST_MODIFIED_BY: &str = "iam.rbc.example/last-modified-by";

/// Fields the owning team may change without an admin. Everything else in the
/// spec is admin-only (enforced at admission, re-checked by the controller).
pub const OWNER_EDITABLE: &[&str] = &["redirectURIs"];

#[derive(Debug, Clone)]
pub struct Policy {
    /// Prefix on every registration this controller owns.
    pub name_prefix: String,
    /// Redirect URI hosts must equal or end with one of these (".apps.example.com").
    pub allowed_redirect_domains: Vec<String>,
    /// Off by default: loopback redirects are a dev convenience, not a prod pattern.
    pub allow_localhost: bool,
    /// Upper bound on secret lifetime, below Entra's own cap.
    pub max_secret_lifetime: Duration,
    /// Require a valid approval stamp before touching Entra.
    pub require_approval: bool,
    /// `ClusterSecretStore`s an IAMClient may push to. Empty: pushing is refused.
    pub allowed_push_stores: Vec<String>,
    /// Store used when `spec.pushSecret.clusterSecretStore` is omitted.
    pub default_push_store: Option<String>,
    /// OpenBao path prefix; the remote key is `<prefix><namespace>/<name>`.
    pub push_path_prefix: String,
    /// `PushSecret.spec.refreshInterval`; bounds how long a rotation takes to reach OpenBao.
    pub push_refresh_interval: String,
}

impl Policy {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            name_prefix: get("NAME_PREFIX").unwrap_or_else(|| "charter-".into()),
            allowed_redirect_domains: get("ALLOWED_REDIRECT_DOMAINS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            allow_localhost: get("ALLOW_LOCALHOST_REDIRECTS").as_deref() == Some("true"),
            max_secret_lifetime: Duration::days(
                get("MAX_SECRET_LIFETIME_DAYS")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(180),
            ),
            // Fail closed: approval is required unless explicitly disabled (dev only).
            require_approval: get("REQUIRE_APPROVAL").as_deref() != Some("false"),
            allowed_push_stores: get("ALLOWED_PUSH_SECRET_STORES")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            default_push_store: get("DEFAULT_PUSH_SECRET_STORE"),
            push_path_prefix: get("PUSH_SECRET_PATH_PREFIX").unwrap_or_else(|| "charter/".into()),
            push_refresh_interval: get("PUSH_SECRET_REFRESH_INTERVAL")
                .unwrap_or_else(|| "1m".into()),
        }
    }

    pub fn check_redirect(&self, uri: &str) -> Result<(), String> {
        let lower = uri.to_lowercase();
        let (scheme, rest) = lower
            .split_once("://")
            .ok_or(format!("not an absolute URI: {uri}"))?;
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host); // drop userinfo
        let host_only = host.split(':').next().unwrap_or_default();
        if rest.contains('*') {
            return Err(format!("wildcard redirect URIs are not allowed: {uri}"));
        }
        if host_only == "localhost" || host_only == "127.0.0.1" {
            return if self.allow_localhost {
                Ok(())
            } else {
                Err(format!(
                    "loopback redirect URIs are disabled by policy: {uri}"
                ))
            };
        }
        if scheme != "https" {
            return Err(format!("redirect URI must use https: {uri}"));
        }
        let allowed = self.allowed_redirect_domains.iter().any(|d| {
            let d = d.trim_start_matches('.');
            host_only == d || host_only.ends_with(&format!(".{d}"))
        });
        if allowed {
            Ok(())
        } else {
            Err(format!(
                "redirect host {host_only} is not in the allowed domains"
            ))
        }
    }

    /// The `ClusterSecretStore` a push request resolves to, if policy allows it.
    pub fn resolve_push_store(&self, requested: Option<&str>) -> Result<String, String> {
        let store = requested
            .map(str::to_string)
            .or_else(|| self.default_push_store.clone())
            .ok_or("pushSecret has no clusterSecretStore and the controller has no default")?;
        if self.allowed_push_stores.iter().any(|s| s == &store) {
            Ok(store)
        } else {
            Err(format!(
                "ClusterSecretStore {store} is not in the allowed push stores"
            ))
        }
    }

    /// Remote key for a client. Fixed by the controller so a team cannot
    /// write into another team's path.
    pub fn push_remote_key(&self, namespace: &str, name: &str) -> String {
        format!("{}{namespace}/{name}", self.push_path_prefix)
    }

    pub fn check_lifetime(&self, d: Duration) -> Result<(), String> {
        if d > self.max_secret_lifetime {
            Err(format!(
                "secretRotation {}d exceeds the policy maximum of {}d",
                d.num_days(),
                self.max_secret_lifetime.num_days()
            ))
        } else {
            Ok(())
        }
    }
}

/// SHA-256 over the canonical JSON of the spec. This is what an approver signs off.
pub fn spec_hash(spec: &IAMClientSpec) -> String {
    let v = serde_json::to_value(spec).unwrap_or_default();
    hex::encode(Sha256::digest(canonical(&v).as_bytes()))
}

/// Hash of the admin-only part of the spec. A change here needs a new approval.
pub fn admin_hash(spec: &IAMClientSpec) -> String {
    let mut v = serde_json::to_value(spec).unwrap_or_default();
    if let Some(m) = v.as_object_mut() {
        for k in OWNER_EDITABLE {
            m.remove(*k);
        }
    }
    hex::encode(Sha256::digest(canonical(&v).as_bytes()))
}

/// JSON with object keys sorted, so the hash does not depend on field order.
fn canonical(v: &serde_json::Value) -> String {
    use serde_json::Value::*;
    match v {
        Object(m) => {
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort();
            let parts: Vec<std::string::String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical(&m[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct Approval {
    pub requested_by: Option<String>,
    pub approved_by: Option<String>,
    pub change_ref: Option<String>,
    pub last_modified_by: Option<String>,
}

impl Approval {
    pub fn from(o: &IAMClient) -> Self {
        let a = o.annotations();
        let get = |k: &str| {
            a.get(k)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        Self {
            requested_by: get(ANN_REQUESTED_BY),
            approved_by: get(ANN_APPROVED_BY),
            change_ref: get(ANN_CHANGE_REF),
            last_modified_by: get(ANN_LAST_MODIFIED_BY),
        }
    }

    /// Valid only if it names a requester, a different approver and a change reference.
    pub fn verify(&self) -> Result<(), String> {
        let req = self.requested_by.as_deref().ok_or("missing requested-by")?;
        let appr = self.approved_by.as_deref().ok_or("missing approved-by")?;
        self.change_ref.as_deref().ok_or("missing change-ref")?;
        if req.eq_ignore_ascii_case(appr) {
            return Err("separation of duties: approver is the requester".into());
        }
        Ok(())
    }
}

/// What kind of change this reconcile applies, which decides whether an admin
/// approval is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Nothing applied yet: admin approval required.
    Create,
    /// Admin-only fields differ from what was last applied: a new approval
    /// (new change-ref) is required.
    AdminChange,
    /// Only owner-editable fields changed, or nothing changed.
    OwnerChange,
}

pub fn classify(applied_admin_hash: Option<&str>, current_admin_hash: &str) -> ChangeKind {
    match applied_admin_hash {
        None => ChangeKind::Create,
        Some(h) if h != current_admin_hash => ChangeKind::AdminChange,
        _ => ChangeKind::OwnerChange,
    }
}

/// The approval gate. `last_change_ref` is the change the current state was applied under.
pub fn gate(kind: ChangeKind, a: &Approval, last_change_ref: Option<&str>) -> Result<(), String> {
    match kind {
        ChangeKind::OwnerChange => Ok(()),
        ChangeKind::Create => a.verify(),
        ChangeKind::AdminChange => {
            a.verify()?;
            if a.change_ref.as_deref() == last_change_ref {
                return Err("admin-only fields changed without a new change-ref".into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            name_prefix: "charter-".into(),
            allowed_redirect_domains: vec![".apps.example.com".into()],
            allow_localhost: false,
            max_secret_lifetime: Duration::days(180),
            require_approval: true,
            allowed_push_stores: vec!["openbao".into()],
            default_push_store: Some("openbao".into()),
            push_path_prefix: "charter/".into(),
            push_refresh_interval: "1m".into(),
        }
    }

    #[test]
    fn push_stores() {
        let mut p = policy();
        assert_eq!(p.resolve_push_store(None).unwrap(), "openbao");
        assert_eq!(p.resolve_push_store(Some("openbao")).unwrap(), "openbao");
        assert!(p.resolve_push_store(Some("team-store")).is_err());
        p.default_push_store = None;
        assert!(p.resolve_push_store(None).is_err());
        // Fail closed: no allow-list means no pushing at all.
        p.allowed_push_stores.clear();
        p.default_push_store = Some("openbao".into());
        assert!(p.resolve_push_store(None).is_err());
        assert_eq!(
            p.push_remote_key("team-a", "portal"),
            "charter/team-a/portal"
        );
    }

    #[test]
    fn redirects() {
        let p = policy();
        assert!(p.check_redirect("https://pay.apps.example.com/cb").is_ok());
        assert!(p.check_redirect("https://apps.example.com/cb").is_ok());
        assert!(p.check_redirect("http://pay.apps.example.com/cb").is_err());
        assert!(p.check_redirect("https://evil.com/cb").is_err());
        assert!(
            p.check_redirect("https://pay.apps.example.com.evil.com/cb")
                .is_err()
        );
        assert!(
            p.check_redirect("https://apps.example.com@evil.com/cb")
                .is_err()
        );
        assert!(p.check_redirect("https://evilapps.example.com/cb").is_err());
        assert!(p.check_redirect("https://*.apps.example.com/cb").is_err());
        assert!(p.check_redirect("http://localhost:8080/cb").is_err());
        let mut dev = policy();
        dev.allow_localhost = true;
        assert!(dev.check_redirect("http://localhost:8080/cb").is_ok());
    }

    #[test]
    fn approval() {
        let ok = Approval {
            requested_by: Some("alice".into()),
            approved_by: Some("bob".into()),
            change_ref: Some("CHG0012345".into()),
            last_modified_by: None,
        };
        assert!(ok.verify().is_ok());
        let sod = Approval {
            approved_by: Some("ALICE".into()),
            ..ok.clone()
        };
        assert!(sod.verify().is_err());
        let no_ref = Approval {
            change_ref: None,
            ..ok.clone()
        };
        assert!(no_ref.verify().is_err());

        // Owner edits need nothing; creation and admin changes need approval.
        let none = Approval {
            requested_by: None,
            approved_by: None,
            change_ref: None,
            last_modified_by: Some("carol".into()),
        };
        assert!(gate(ChangeKind::OwnerChange, &none, Some("CHG1")).is_ok());
        assert!(gate(ChangeKind::Create, &none, None).is_err());
        assert!(gate(ChangeKind::Create, &ok, None).is_ok());
        assert!(gate(ChangeKind::AdminChange, &ok, Some("CHG0012345")).is_err());
        assert!(gate(ChangeKind::AdminChange, &ok, Some("CHG0000001")).is_ok());
    }

    #[test]
    fn owner_fields_do_not_change_admin_hash() {
        let y = |r: &str, g: &str| -> IAMClientSpec {
            serde_norway::from_str(&format!(
                "displayName: X\nredirectURIs: [{r}]\ngroups: [{g}]\nowners: [o1]\n"
            ))
            .unwrap()
        };
        assert_eq!(
            admin_hash(&y("https://a/cb", "G1")),
            admin_hash(&y("https://b/cb", "G1"))
        );
        assert_ne!(
            admin_hash(&y("https://a/cb", "G1")),
            admin_hash(&y("https://a/cb", "G2"))
        );
        // pushSecret is admin-only, and adding the field to the CRD must not
        // change the hash of clients that do not use it (no forced re-approval).
        let base = "displayName: X\nowners: [o1]\n";
        let without: IAMClientSpec = serde_norway::from_str(base).unwrap();
        let with: IAMClientSpec =
            serde_norway::from_str(&format!("{base}pushSecret: {{}}\n")).unwrap();
        assert_ne!(admin_hash(&without), admin_hash(&with));
        assert!(
            !serde_json::to_string(&without)
                .unwrap()
                .contains("pushSecret")
        );
        assert_eq!(classify(None, "h"), ChangeKind::Create);
        assert_eq!(classify(Some("h"), "h"), ChangeKind::OwnerChange);
        assert_eq!(classify(Some("g"), "h"), ChangeKind::AdminChange);
    }

    #[test]
    fn canonical_is_order_independent() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":[{"y":2,"x":1}]}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"a":[{"x":1,"y":2}],"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
    }
}
