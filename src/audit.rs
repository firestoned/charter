//! Audit trail.
//!
//! Every Entra mutation is bracketed by two records: `attempted` before the
//! Graph call and `succeeded` or `failed` after it, so a crash mid-call still
//! leaves evidence of intent. Policy and approval decisions are recorded too.
//!
//! Records go to the `audit` tracing target as single JSON lines (ship them to
//! the SIEM / WORM store from stdout; never mix with debug logs) and are
//! mirrored as Kubernetes Events on the IAMClient for operators.
//!
//! Each record carries a per-process sequence number and a SHA-256 chain over
//! the previous record, so gaps or edits are detectable within a process run.
//! The SIEM's immutable storage is the system of record; the chain is a
//! tamper-evidence aid, not a replacement for it.

use chrono::Utc;
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::future::Future;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Attempted,
    Succeeded,
    Failed,
    Denied,
    Info,
}

/// Who/what a record is about. Built once per reconcile.
#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub generation: Option<i64>,
    pub spec_hash: String,
    pub admin_hash: String,
    /// Kubernetes user who last changed the object (admission-stamped).
    pub last_modified_by: Option<String>,
    pub unique_name: String,
    pub requested_by: Option<String>,
    pub approved_by: Option<String>,
    pub change_ref: Option<String>,
    /// Correlates every record of one reconcile pass.
    pub correlation_id: String,
}

#[derive(Serialize)]
struct Record<'a> {
    schema: &'static str,
    seq: u64,
    prev_hash: &'a str,
    time: String,
    actor: &'a str,
    action: &'a str,
    outcome: Outcome,
    subject: &'a Subject,
    details: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

pub struct Auditor {
    /// The controller's own identity (Entra client ID of the workload identity).
    actor: String,
    chain: Mutex<(u64, String)>,
    recorder: Recorder,
}

impl Auditor {
    pub fn new(client: kube::Client, actor: String) -> Self {
        let reporter = Reporter {
            controller: "charter-api".into(),
            instance: std::env::var("POD_NAME").ok(),
        };
        Self {
            actor,
            chain: Mutex::new((0, "0".repeat(64))),
            recorder: Recorder::new(client, reporter),
        }
    }

    pub async fn record(
        &self,
        obj_ref: &k8s_openapi::api::core::v1::ObjectReference,
        subject: &Subject,
        action: &str,
        outcome: Outcome,
        details: Value,
        error: Option<&str>,
    ) {
        let line = {
            let mut chain = self.chain.lock().await;
            chain.0 += 1;
            let rec = Record {
                schema: "charter.audit/v1",
                seq: chain.0,
                prev_hash: &chain.1,
                time: Utc::now().to_rfc3339(),
                actor: &self.actor,
                action,
                outcome,
                subject,
                details: &details,
                error,
            };
            let line = serde_json::to_string(&rec).unwrap_or_default();
            chain.1 = hex::encode(Sha256::digest(line.as_bytes()));
            line
        };
        tracing::info!(target: "audit", audit = %line);

        // Mirror to a Kubernetes Event. Best effort: the audit log is the record.
        let type_ = match outcome {
            Outcome::Failed | Outcome::Denied => EventType::Warning,
            _ => EventType::Normal,
        };
        let ev = Event {
            type_,
            reason: format!("{action}:{outcome:?}"),
            note: Some(
                error
                    .map(|e| truncate(e, 900))
                    .unwrap_or_else(|| truncate(&details.to_string(), 900)),
            ),
            action: action.to_string(),
            secondary: None,
        };
        if let Err(e) = self.recorder.publish(&ev, obj_ref).await {
            tracing::warn!(error = %e, "failed to publish audit event to Kubernetes");
        }
    }

    /// Run a mutating call between an `attempted` and a result record.
    pub async fn audited<T, E: std::fmt::Display, F: Future<Output = Result<T, E>>>(
        &self,
        obj_ref: &k8s_openapi::api::core::v1::ObjectReference,
        subject: &Subject,
        action: &str,
        details: Value,
        fut: F,
    ) -> Result<T, E> {
        self.record(
            obj_ref,
            subject,
            action,
            Outcome::Attempted,
            details.clone(),
            None,
        )
        .await;
        let res = fut.await;
        match &res {
            Ok(_) => {
                self.record(obj_ref, subject, action, Outcome::Succeeded, details, None)
                    .await
            }
            Err(e) => {
                let msg = e.to_string();
                self.record(
                    obj_ref,
                    subject,
                    action,
                    Outcome::Failed,
                    details,
                    Some(&msg),
                )
                .await
            }
        }
        res
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
