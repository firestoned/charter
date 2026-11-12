//! Platform policy (set by Enterprise IAM via controller config) and the
//! approval gate checked before any Entra mutation.

use crate::crd::{IAMClient, IAMClientSpec};
use chrono::Duration;
use kube::ResourceExt;
use sha2::{Digest, Sha256};

pub const ANN_REQUESTED_BY: &str = "iam.rbc.example/requested-by";
pub const ANN_APPROVED_BY: &str = "iam.rbc.example/approved-by";
pub const ANN_CHANGE_REF: &str = "iam.rbc.example/change-ref";
pub const ANN_APPROVED_HASH: &str = "iam.rbc.example/approved-spec-hash";

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
}

impl Policy {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            name_prefix: get("NAME_PREFIX").unwrap_or_else(|| "iamaas-".into()),
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
    pub approved_hash: Option<String>,
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
            approved_hash: get(ANN_APPROVED_HASH),
        }
    }

    /// Valid only if it names a requester, a different approver, a change
    /// reference, and the hash of exactly the spec being applied.
    pub fn verify(&self, current_hash: &str) -> Result<(), String> {
        let req = self.requested_by.as_deref().ok_or("missing requested-by")?;
        let appr = self.approved_by.as_deref().ok_or("missing approved-by")?;
        self.change_ref.as_deref().ok_or("missing change-ref")?;
        let h = self
            .approved_hash
            .as_deref()
            .ok_or("missing approved-spec-hash")?;
        if req.eq_ignore_ascii_case(appr) {
            return Err("separation of duties: approver is the requester".into());
        }
        if h != current_hash {
            return Err("spec changed since approval (hash mismatch)".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            name_prefix: "iamaas-".into(),
            allowed_redirect_domains: vec![".apps.example.com".into()],
            allow_localhost: false,
            max_secret_lifetime: Duration::days(180),
            require_approval: true,
        }
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
            approved_hash: Some("abc".into()),
        };
        assert!(ok.verify("abc").is_ok());
        assert!(ok.verify("def").is_err());
        let sod = Approval {
            approved_by: Some("ALICE".into()),
            ..ok.clone()
        };
        assert!(sod.verify("abc").is_err());
        let no_ref = Approval {
            change_ref: None,
            ..ok
        };
        assert!(no_ref.verify("abc").is_err());
    }

    #[test]
    fn canonical_is_order_independent() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":[{"y":2,"x":1}]}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"a":[{"x":1,"y":2}],"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
    }
}
