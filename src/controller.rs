//! Reconcile loop: IAMClient -> Entra app registration + service principal +
//! owners + client secret + Kubernetes Secret carrying credentials and Dex config.
//!
//! Order of operations is chosen for auditability and fail-closed behaviour:
//! 1. policy check, 2. approval check, 3. read Entra state and record drift,
//! 4. audited mutations, 5. deliver secret, 6. revoke stale secrets, 7. status.
//!
//! Nothing in Entra changes unless 1 and 2 pass.

use crate::audit::{Auditor, Outcome, Subject};
use crate::crd::{Condition, DeletionPolicy, IAMClient, IAMClientStatus};
use crate::graph::{Application, Graph, GraphError};
use crate::policy::{Approval, ChangeKind, Policy, admin_hash, classify, gate, spec_hash};
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{ObjectMeta, Patch, PatchParams},
    runtime::{
        Controller,
        controller::Action,
        finalizer::{Event, finalizer},
        watcher,
    },
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

const FINALIZER: &str = "iam.rbc.example/entra-cleanup";
const MANAGER: &str = "entra-controller";
const ANN_KEY_ID: &str = "iam.rbc.example/key-id";
const ANN_PREV_KEY_ID: &str = "iam.rbc.example/previous-key-id";
const ANN_ROTATED_AT: &str = "iam.rbc.example/rotated-at";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("graph: {0}")]
    Graph(#[from] GraphError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("finalizer: {0}")]
    Finalizer(#[source] Box<kube::runtime::finalizer::Error<Error>>),
    #[error("invalid: {0}")]
    Invalid(String),
}

pub struct Ctx {
    pub client: Client,
    pub graph: Graph,
    pub policy: Policy,
    pub audit: Auditor,
    /// How long a rotated-out secret stays valid so consumers can pick up the new one.
    pub rotation_grace: ChronoDuration,
}

pub async fn run(ctx: Arc<Ctx>) {
    let clients: Api<IAMClient> = Api::all(ctx.client.clone());
    let secrets: Api<Secret> = Api::all(ctx.client.clone());
    Controller::new(clients, watcher::Config::default())
        .owns(
            secrets,
            watcher::Config::default().labels("app.kubernetes.io/managed-by=entra-controller"),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => {
                    tracing::debug!(object = %obj.name, ns = ?obj.namespace, "reconciled")
                }
                Err(e) => tracing::warn!(error = %e, "reconcile failed"),
            }
        })
        .await;
}

async fn reconcile(obj: Arc<IAMClient>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = obj
        .namespace()
        .ok_or_else(|| Error::Invalid("IAMClient must be namespaced".into()))?;
    let api: Api<IAMClient> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            Event::Apply(o) => apply(&o, &ctx).await,
            Event::Cleanup(o) => cleanup(&o, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn error_policy(_obj: Arc<IAMClient>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    match err {
        Error::Invalid(_) => Action::requeue(Duration::from_secs(300)),
        _ => Action::requeue(Duration::from_secs(30)),
    }
}

fn unique_name(prefix: &str, o: &IAMClient) -> String {
    format!(
        "{prefix}{}-{}",
        o.namespace().unwrap_or_default(),
        o.name_any()
    )
}

fn subject(o: &IAMClient, ctx: &Ctx) -> Subject {
    let a = Approval::from(o);
    Subject {
        namespace: o.namespace().unwrap_or_default(),
        name: o.name_any(),
        uid: o.uid().unwrap_or_default(),
        generation: o.meta().generation,
        spec_hash: spec_hash(&o.spec),
        admin_hash: admin_hash(&o.spec),
        last_modified_by: a.last_modified_by,
        unique_name: unique_name(&ctx.policy.name_prefix, o),
        requested_by: a.requested_by,
        approved_by: a.approved_by,
        change_ref: a.change_ref,
        correlation_id: uuid::Uuid::new_v4().to_string(),
    }
}

/// Every policy rule, all violations reported at once.
fn check_policy(o: &IAMClient, p: &Policy) -> Result<ChronoDuration, Vec<String>> {
    let mut v = Vec::new();
    let lifetime = parse_duration(&o.spec.secret_rotation).map_err(|e| vec![e])?;
    if let Err(e) = p.check_lifetime(lifetime) {
        v.push(e);
    }
    if o.spec.owners.is_empty() {
        v.push("at least one human owner is required for accountability".into());
    }
    for uri in &o.spec.redirect_uris {
        if let Err(e) = p.check_redirect(uri) {
            v.push(e);
        }
    }
    if let Some(d) = &o.spec.dex
        && let Err(e) = p.check_redirect(&d.issuer_url)
    {
        v.push(format!("dex issuer: {e}"));
    }
    if v.is_empty() { Ok(lifetime) } else { Err(v) }
}

async fn apply(o: &IAMClient, ctx: &Ctx) -> Result<Action, Error> {
    let ns = o.namespace().unwrap_or_default();
    let name = o.name_any();
    let spec = &o.spec;
    let status = o.status.clone().unwrap_or_default();
    let subj = subject(o, ctx);
    let oref = o.object_ref(&());
    let au = &ctx.audit;

    // 1. Policy. Nothing in Entra changes when this fails.
    let lifetime = match check_policy(o, &ctx.policy) {
        Ok(l) => l,
        Err(violations) => {
            au.record(
                &oref,
                &subj,
                "policy_check",
                Outcome::Denied,
                json!({ "violations": violations }),
                None,
            )
            .await;
            set_not_ready(o, ctx, &status, "PolicyViolation", &violations.join("; ")).await?;
            return Ok(Action::await_change());
        }
    };

    // 2. Approval. Creation and admin-only changes need an admin approval with
    //    a change reference; owner-editable changes (redirect URIs) are
    //    applied on the owner's authority and audited with who made them.
    let kind = classify(status.applied_admin_hash.as_deref(), &subj.admin_hash);
    let generation_changed = status.observed_generation != o.meta().generation;
    if ctx.policy.require_approval {
        if let Err(why) = gate(kind, &Approval::from(o), status.change_ref.as_deref()) {
            au.record(
                &oref,
                &subj,
                "approval_check",
                Outcome::Denied,
                json!({ "change": format!("{kind:?}"), "reason": why }),
                None,
            )
            .await;
            set_not_ready(o, ctx, &status, "PendingApproval", &why).await?;
            return Ok(Action::await_change());
        }
        if generation_changed {
            let basis = if kind == ChangeKind::OwnerChange {
                "owner"
            } else {
                "admin_approval"
            };
            au.record(
                &oref,
                &subj,
                "approval_check",
                Outcome::Info,
                json!({ "change": format!("{kind:?}"), "authority": basis }),
                None,
            )
            .await;
        }
    } else if generation_changed {
        au.record(
            &oref,
            &subj,
            "approval_check",
            Outcome::Info,
            json!({ "reason": "approval disabled by config" }),
            None,
        )
        .await;
    }

    // 3. App registration: create if missing, correct drift if changed out of band.
    let entra_redirects: Vec<String> = match &spec.dex {
        Some(d) => vec![format!("{}/callback", d.issuer_url.trim_end_matches('/'))],
        None => spec.redirect_uris.clone(),
    };
    let display_name = format!("{}{}", ctx.policy.name_prefix, spec.display_name);
    let group_claims = if spec.groups.is_empty() {
        "None"
    } else {
        "ApplicationGroup"
    };
    let body = json!({
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "web": { "redirectUris": entra_redirects },
        "groupMembershipClaims": group_claims,
        "tags": ["iamaas", format!("k8s:{ns}/{name}"), format!("spec:{}", &subj.spec_hash[..16])],
        "notes": format!(
            "Managed by entra-controller from IAMClient {ns}/{name}. Change {}. Do not edit by hand: changes are reverted and audited.",
            subj.change_ref.as_deref().unwrap_or("n/a")
        ),
    });
    let current = ctx.graph.get_application(&subj.unique_name).await?;
    let app = match current {
        None => {
            au.audited(
                &oref,
                &subj,
                "create_application",
                json!({ "displayName": display_name, "redirectUris": entra_redirects }),
                ctx.graph.upsert_application(&subj.unique_name, &body),
            )
            .await?
        }
        Some(cur) => {
            let drift = diff(&cur, &display_name, &entra_redirects, group_claims);
            if drift.is_empty() {
                cur
            } else {
                au.record(
                    &oref,
                    &subj,
                    "drift_detected",
                    Outcome::Info,
                    json!({ "fields": drift }),
                    None,
                )
                .await;
                au.audited(
                    &oref,
                    &subj,
                    "update_application",
                    json!({ "fields": drift }),
                    ctx.graph.upsert_application(&subj.unique_name, &body),
                )
                .await?
            }
        }
    };

    // 4. Service principal.
    let sp_id = match ctx.graph.get_service_principal(&app.app_id).await? {
        Some(id) => id,
        None => {
            au.audited(
                &oref,
                &subj,
                "create_service_principal",
                json!({ "appId": app.app_id }),
                ctx.graph.create_service_principal(&app.app_id),
            )
            .await?
        }
    };

    // 5. Owners: exactly spec.owners plus the controller itself.
    let me = ctx.graph.self_object_id().await?;
    let want: BTreeSet<String> = spec.owners.iter().cloned().chain([me.clone()]).collect();
    let have: BTreeSet<String> = ctx.graph.list_owners(&app.id).await?.into_iter().collect();
    for id in want.difference(&have) {
        au.audited(
            &oref,
            &subj,
            "add_owner",
            json!({ "ownerId": id }),
            ctx.graph.add_owner(&app.id, id),
        )
        .await?;
    }
    for id in have.difference(&want).filter(|id| **id != me) {
        au.record(
            &oref,
            &subj,
            "drift_detected",
            Outcome::Info,
            json!({ "unexpectedOwner": id }),
            None,
        )
        .await;
        au.audited(
            &oref,
            &subj,
            "remove_owner",
            json!({ "ownerId": id }),
            ctx.graph.remove_owner(&app.id, id),
        )
        .await?;
    }

    // 6. Client secret. The Secret's annotations say which key is delivered.
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
    let secret_name = format!("{name}-entra");
    let existing = secrets.get_opt(&secret_name).await?;
    let ann = existing
        .as_ref()
        .map(|s| s.annotations().clone())
        .unwrap_or_default();
    let data = existing
        .as_ref()
        .and_then(|s| s.data.clone())
        .unwrap_or_default();
    let delivered_key = ann.get(ANN_KEY_ID).cloned();
    let delivered_cred = delivered_key
        .as_ref()
        .and_then(|k| app.password_credentials.iter().find(|p| &p.key_id == k));
    let now = Utc::now();
    let rotate_due = delivered_cred
        .and_then(|c| c.end_date_time)
        .is_none_or(|end| now >= end - lifetime / 3);
    let needs_secret =
        delivered_cred.is_none() || !data.contains_key("client-secret") || rotate_due;

    let (client_secret, key_id, expires_at, prev_key, rotated_at): (
        SecretString,
        String,
        DateTime<Utc>,
        Option<String>,
        String,
    ) = if needs_secret {
        let pw = au
                .audited(&oref, &subj, "add_password", json!({ "lifetimeDays": lifetime.num_days(), "reason": if delivered_cred.is_none() { "initial_or_missing" } else { "rotation" } }),
                    ctx.graph.add_password(&app.id, &format!("iamaas {}", now.format("%Y-%m-%d")), now + lifetime))
                .await?;
        (
            pw.secret_text,
            pw.key_id,
            pw.end_date_time,
            delivered_key.clone(),
            now.to_rfc3339(),
        )
    } else {
        let s = SecretString::from(String::from_utf8_lossy(&data["client-secret"].0).into_owned());
        let cred = delivered_cred.expect("checked above");
        (
            s,
            cred.key_id.clone(),
            cred.end_date_time.unwrap_or(now),
            ann.get(ANN_PREV_KEY_ID).cloned(),
            ann.get(ANN_ROTATED_AT).cloned().unwrap_or_default(),
        )
    };

    // 7. Deliver. TODO: OpenBao KV v2 sink; split Dex and Entra secrets.
    let dex_client_secret = data
        .get("dex-client-secret")
        .map(|b| SecretString::from(String::from_utf8_lossy(&b.0).into_owned()))
        .unwrap_or_else(random_secret);
    let mut out = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        out.insert(k.to_string(), ByteString(v.as_bytes().to_vec()));
    };
    put("tenant-id", &ctx.graph.tenant_id);
    put("client-id", &app.app_id);
    put("client-secret", client_secret.expose_secret());
    put(
        "issuer",
        &format!(
            "https://login.microsoftonline.com/{}/v2.0",
            ctx.graph.tenant_id
        ),
    );
    if let Some(dex) = &spec.dex {
        put("dex-client-secret", dex_client_secret.expose_secret());
        put(
            "dex-config.yaml",
            &dex_config(
                o,
                &dex.issuer_url,
                &ctx.graph.tenant_id,
                &app.app_id,
                &client_secret,
                &dex_client_secret,
            ),
        );
    }
    let mut annotations = BTreeMap::from([
        (ANN_KEY_ID.to_string(), key_id.clone()),
        (ANN_ROTATED_AT.to_string(), rotated_at.clone()),
    ]);
    if let Some(p) = &prev_key {
        annotations.insert(ANN_PREV_KEY_ID.to_string(), p.clone());
    }
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(ns.clone()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                MANAGER.to_string(),
            )])),
            annotations: Some(annotations),
            owner_references: Some(vec![
                o.controller_owner_ref(&())
                    .expect("IAMClient has a name and uid"),
            ]),
            ..Default::default()
        },
        type_: Some("Opaque".into()),
        immutable: None,
        data: Some(out),
        ..Default::default()
    };
    let pp = PatchParams::apply(MANAGER).force();
    let patch = Patch::Apply(&secret);
    let deliver = secrets.patch(&secret_name, &pp, &patch);
    if needs_secret {
        au.audited(
            &oref,
            &subj,
            "deliver_secret",
            json!({ "secret": secret_name, "keyId": key_id }),
            deliver,
        )
        .await?;
    } else {
        deliver.await?;
    }

    // 8. Revoke every password that is not the delivered one, except the previous
    //    one during its grace period. Catches hand-added secrets too.
    let in_grace = DateTime::parse_from_rfc3339(&rotated_at)
        .map(|t| now < t.with_timezone(&Utc) + ctx.rotation_grace)
        .unwrap_or(false);
    let keep_prev = prev_key.filter(|_| in_grace);
    for cred in &app.password_credentials {
        if cred.key_id == key_id || Some(&cred.key_id) == keep_prev.as_ref() {
            continue;
        }
        let reason = if Some(&cred.key_id) == ann.get(ANN_PREV_KEY_ID)
            || Some(&cred.key_id) == delivered_key.as_ref()
        {
            "rotated_out"
        } else {
            "unknown_credential"
        };
        au.audited(
            &oref,
            &subj,
            "remove_password",
            json!({ "keyId": cred.key_id, "reason": reason }),
            ctx.graph.remove_password(&app.id, &cred.key_id),
        )
        .await?;
    }

    // 9. Status, with the approval evidence this state was reached under.
    let new_status = IAMClientStatus {
        app_id: Some(app.app_id.clone()),
        object_id: Some(app.id.clone()),
        service_principal_id: Some(sp_id),
        secret_key_id: Some(key_id),
        secret_expires_at: Some(expires_at.to_rfc3339()),
        secret_name: Some(secret_name),
        observed_generation: o.meta().generation,
        applied_spec_hash: Some(subj.spec_hash.clone()),
        applied_admin_hash: Some(subj.admin_hash.clone()),
        // Keep the approval the admin-only state was applied under; owner edits don't change it.
        approved_by: if kind == ChangeKind::OwnerChange {
            status.approved_by.clone()
        } else {
            subj.approved_by.clone()
        },
        change_ref: if kind == ChangeKind::OwnerChange {
            status.change_ref.clone()
        } else {
            subj.change_ref.clone()
        },
        conditions: vec![condition(
            &status,
            o,
            "True",
            "Reconciled",
            "Entra registration matches the approved spec",
        )],
    };
    patch_status(o, ctx, &new_status).await?;

    // Wake for the next rotation or grace expiry, and at least hourly to catch drift.
    let next_rotation = (expires_at - lifetime / 3 - Utc::now())
        .to_std()
        .unwrap_or_default();
    Ok(Action::requeue(
        next_rotation.clamp(Duration::from_secs(60), Duration::from_secs(3600)),
    ))
}

async fn cleanup(o: &IAMClient, ctx: &Ctx) -> Result<Action, Error> {
    let subj = subject(o, ctx);
    let oref = o.object_ref(&());
    let au = &ctx.audit;
    let Some(app) = ctx.graph.get_application(&subj.unique_name).await? else {
        au.record(
            &oref,
            &subj,
            "cleanup",
            Outcome::Info,
            json!({ "reason": "application already absent" }),
            None,
        )
        .await;
        return Ok(Action::await_change());
    };
    match o.spec.deletion_policy {
        DeletionPolicy::Delete => {
            au.audited(
                &oref,
                &subj,
                "delete_application",
                json!({ "appId": app.app_id, "softDeleteDays": 30 }),
                ctx.graph.delete_application(&subj.unique_name),
            )
            .await?;
        }
        DeletionPolicy::Retain => {
            // Keep the registration as evidence, but leave it unusable.
            for cred in &app.password_credentials {
                au.audited(
                    &oref,
                    &subj,
                    "remove_password",
                    json!({ "keyId": cred.key_id, "reason": "deletion_policy_retain" }),
                    ctx.graph.remove_password(&app.id, &cred.key_id),
                )
                .await?;
            }
            au.record(
                &oref,
                &subj,
                "retain_application",
                Outcome::Info,
                json!({ "appId": app.app_id }),
                None,
            )
            .await;
        }
    }
    Ok(Action::await_change())
}

/// Fields that differ between Entra and the desired state.
fn diff(
    cur: &Application,
    display_name: &str,
    redirects: &[String],
    group_claims: &str,
) -> Vec<&'static str> {
    let mut d = Vec::new();
    if cur.display_name.as_deref() != Some(display_name) {
        d.push("displayName");
    }
    if cur.sign_in_audience.as_deref() != Some("AzureADMyOrg") {
        d.push("signInAudience");
    }
    if !cur
        .group_membership_claims
        .as_deref()
        .unwrap_or("None")
        .eq_ignore_ascii_case(group_claims)
    {
        d.push("groupMembershipClaims");
    }
    let mut have: Vec<_> = cur.web.clone().unwrap_or_default().redirect_uris;
    let mut want = redirects.to_vec();
    have.sort();
    want.sort();
    if have != want {
        d.push("web.redirectUris");
    }
    d
}

async fn set_not_ready(
    o: &IAMClient,
    ctx: &Ctx,
    prev: &IAMClientStatus,
    reason: &str,
    msg: &str,
) -> Result<(), Error> {
    let mut s = prev.clone();
    s.observed_generation = o.meta().generation;
    s.conditions = vec![condition(prev, o, "False", reason, msg)];
    patch_status(o, ctx, &s).await
}

async fn patch_status(o: &IAMClient, ctx: &Ctx, s: &IAMClientStatus) -> Result<(), Error> {
    let api: Api<IAMClient> =
        Api::namespaced(ctx.client.clone(), &o.namespace().unwrap_or_default());
    api.patch_status(
        &o.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({ "status": s })),
    )
    .await?;
    Ok(())
}

fn condition(
    prev: &IAMClientStatus,
    o: &IAMClient,
    status: &str,
    reason: &str,
    message: &str,
) -> Condition {
    // Keep lastTransitionTime stable unless the status actually flips.
    let since = prev
        .conditions
        .iter()
        .find(|c| c.type_ == "Ready" && c.status == status)
        .map(|c| c.last_transition_time.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    Condition {
        type_: "Ready".into(),
        status: status.into(),
        reason: reason.into(),
        message: message.chars().take(1000).collect(),
        last_transition_time: since,
        observed_generation: o.meta().generation,
    }
}

/// `90d`, `720h`, `30m`.
pub fn parse_duration(s: &str) -> Result<ChronoDuration, String> {
    let bad = || format!("secretRotation must look like 90d or 720h, got {s:?}");
    let (n, unit) = s.split_at(s.len().checked_sub(1).ok_or_else(bad)?);
    let n: i64 = n.parse().map_err(|_| bad())?;
    let d = match unit {
        "d" => ChronoDuration::days(n),
        "h" => ChronoDuration::hours(n),
        "m" => ChronoDuration::minutes(n),
        _ => return Err(bad()),
    };
    // Entra caps secrets at 2 years; the platform policy cap is checked separately.
    if d < ChronoDuration::hours(1) || d > ChronoDuration::days(730) {
        return Err(bad());
    }
    Ok(d)
}

fn random_secret() -> SecretString {
    let mut buf = [0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    buf.fill(0);
    SecretString::from(s)
}

/// Dex fragment: the Microsoft connector (Dex -> Entra) and the static client
/// (team app -> Dex). A Dex config renderer merges fragments per issuer.
fn dex_config(
    o: &IAMClient,
    issuer: &str,
    tenant: &str,
    app_id: &str,
    entra_secret: &SecretString,
    dex_secret: &SecretString,
) -> String {
    let issuer = issuer.trim_end_matches('/');
    let v: Value = json!({
        "connectors": [{
            "type": "microsoft",
            "id": "entra",
            "name": "Entra ID",
            "config": {
                "clientID": app_id,
                "clientSecret": entra_secret.expose_secret(),
                "redirectURI": format!("{issuer}/callback"),
                "tenant": tenant,
                "groups": o.spec.groups,
                "onlySecurityGroups": true,
            }
        }],
        "staticClients": [{
            "id": o.name_any(),
            "name": o.spec.display_name,
            "secret": dex_secret.expose_secret(),
            "redirectURIs": o.spec.redirect_uris,
        }]
    });
    serde_norway::to_string(&v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90d").unwrap(), ChronoDuration::days(90));
        assert_eq!(parse_duration("720h").unwrap(), ChronoDuration::hours(720));
        assert!(parse_duration("0d").is_err());
        assert!(parse_duration("3y").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("1000d").is_err());
    }

    #[test]
    fn drift() {
        let app = Application {
            id: "o".into(),
            app_id: "a".into(),
            display_name: Some("iamaas-Pay".into()),
            sign_in_audience: Some("AzureADMyOrg".into()),
            group_membership_claims: Some("ApplicationGroup".into()),
            web: Some(crate::graph::Web {
                redirect_uris: vec!["https://b/cb".into(), "https://a/cb".into()],
            }),
            password_credentials: vec![],
        };
        let r = vec!["https://a/cb".to_string(), "https://b/cb".to_string()];
        assert!(diff(&app, "iamaas-Pay", &r, "ApplicationGroup").is_empty());
        assert_eq!(
            diff(&app, "iamaas-Pay", &r[..1], "None"),
            vec!["groupMembershipClaims", "web.redirectUris"]
        );
    }
}
