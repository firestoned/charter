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
use crate::push::{self, SyncState};
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, DynamicObject, ObjectMeta, Patch, PatchParams},
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
const MANAGER: &str = "charter-iam";
const ANN_KEY_ID: &str = "iam.rbc.example/key-id";
const ANN_PREV_KEY_ID: &str = "iam.rbc.example/previous-key-id";
const ANN_ROTATED_AT: &str = "iam.rbc.example/rotated-at";
/// How long after a delivery a missing key is treated as replication lag
/// rather than as a secret deleted out of band.
const STALE_READ_WINDOW: ChronoDuration = ChronoDuration::minutes(10);

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
            watcher::Config::default().labels("app.kubernetes.io/managed-by=charter-iam"),
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
    if let Some(ps) = &o.spec.push_secret
        && let Err(e) = p.resolve_push_store(ps.cluster_secret_store.as_deref())
    {
        v.push(format!("pushSecret: {e}"));
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
        "tags": ["charter", format!("k8s:{ns}/{name}"), format!("spec:{}", &subj.spec_hash[..16])],
        "notes": format!(
            "Managed by charter-iam from IAMClient {ns}/{name}. Change {}. Do not edit by hand: changes are reverted and audited.",
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
    // Graph is eventually consistent: a reconcile right after a rotation can
    // read a password list that does not show the key just delivered. Acting
    // on that read would mint a second secret and revoke the one consumers
    // hold. If the Secret says we delivered a key recently and Graph does not
    // list it yet, change nothing and look again shortly.
    let delivered_recently = ann
        .get(ANN_ROTATED_AT)
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .is_some_and(|t| now - t.with_timezone(&Utc) < STALE_READ_WINDOW);
    if delivered_key.is_some()
        && delivered_cred.is_none()
        && data.contains_key("client-secret")
        && delivered_recently
    {
        tracing::info!(
            ns = %ns, name = %name, key_id = ?delivered_key,
            "delivered key not visible in Graph yet; waiting for replication"
        );
        return Ok(Action::requeue(Duration::from_secs(15)));
    }
    let rotation = rotation_reason(
        delivered_cred.map(|c| c.end_date_time),
        data.contains_key("client-secret"),
        now,
        lifetime,
    );
    let needs_secret = rotation.is_some();

    let (client_secret, key_id, expires_at, prev_key, rotated_at): (
        SecretString,
        String,
        DateTime<Utc>,
        Option<String>,
        String,
    ) = if needs_secret {
        let pw = au
            .audited(
                &oref,
                &subj,
                "add_password",
                json!({ "lifetime": spec.secret_rotation, "reason": rotation }),
                ctx.graph.add_password(
                    &app.id,
                    &format!("charter {}", now.format("%Y-%m-%d")),
                    now + lifetime,
                ),
            )
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
    let pushed_keys: Vec<String> = out.keys().cloned().collect();
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

    // 7b. Optional copy to OpenBao through an ESO PushSecret.
    let rotated_at_t = DateTime::parse_from_rfc3339(&rotated_at)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    let push = reconcile_push(
        o,
        ctx,
        &subj,
        &oref,
        &secret_name,
        &pushed_keys,
        rotated_at_t,
    )
    .await?;
    let push_synced = push.as_ref().is_none_or(|p| p.state == SyncState::Synced);

    // 8. Revoke every password that is not the delivered one, except the previous
    //    one during its grace period, or until OpenBao holds its replacement.
    //    Catches hand-added secrets too.
    let in_grace = now < rotated_at_t + ctx.rotation_grace;
    let keep_prev = prev_key.filter(|_| in_grace || !push_synced);
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
        push_secret_name: push.as_ref().map(|p| p.name.clone()),
        pushed_to: push.as_ref().map(|p| p.pushed_to.clone()),
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
        conditions: {
            let mut c = vec![match push.as_ref().map(|p| &p.state) {
                Some(SyncState::Failed(why)) => condition(
                    &status,
                    o,
                    "Ready",
                    "False",
                    "PushSecretFailed",
                    &format!("Entra is reconciled but the push to OpenBao failed: {why}"),
                ),
                _ => condition(
                    &status,
                    o,
                    "Ready",
                    "True",
                    "Reconciled",
                    "Entra registration matches the approved spec",
                ),
            }];
            if let Some(p) = &push {
                c.push(match &p.state {
                    SyncState::Synced => condition(
                        &status,
                        o,
                        "SecretPushed",
                        "True",
                        "Synced",
                        &format!("credentials pushed to {}", p.pushed_to),
                    ),
                    SyncState::Pending(why) => {
                        condition(&status, o, "SecretPushed", "False", "Pending", why)
                    }
                    SyncState::Failed(why) => {
                        condition(&status, o, "SecretPushed", "False", "Failed", why)
                    }
                });
            }
            c
        },
    };
    patch_status(o, ctx, &new_status).await?;

    // A pending push holds back revocation of the previous secret; look again soon.
    if !push_synced {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

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
    // Garbage collection would remove an owned PushSecret too, but only after
    // the finalizer; delete it here so the OpenBao copy goes in the audit trail.
    if o.status
        .as_ref()
        .is_some_and(|s| s.push_secret_name.is_some())
    {
        delete_push_secret(o, ctx, &subj, &oref, "iamclient_deleted").await?;
    }
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

/// What happened to the OpenBao copy on this reconcile.
struct PushOutcome {
    name: String,
    pushed_to: String,
    state: SyncState,
}

fn push_api(ctx: &Ctx, ns: &str) -> Api<DynamicObject> {
    Api::namespaced_with(ctx.client.clone(), ns, &push::api_resource())
}

/// A missing PushSecret CRD answers 404, like a missing object.
fn is_not_found(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(s) if s.code == 404)
}

/// Create or update the PushSecret for `spec.pushSecret`, or remove a stale
/// one when the field is gone. Applies (and audits) only when the rendered
/// spec changed.
async fn reconcile_push(
    o: &IAMClient,
    ctx: &Ctx,
    subj: &Subject,
    oref: &k8s_openapi::api::core::v1::ObjectReference,
    secret_name: &str,
    keys: &[String],
    since: DateTime<Utc>,
) -> Result<Option<PushOutcome>, Error> {
    let Some(req) = &o.spec.push_secret else {
        let had_one = o
            .status
            .as_ref()
            .is_some_and(|s| s.push_secret_name.is_some());
        if had_one {
            delete_push_secret(o, ctx, subj, oref, "push_secret_removed_from_spec").await?;
        }
        return Ok(None);
    };
    let ns = o.namespace().unwrap_or_default();
    let api = push_api(ctx, &ns);
    // Policy was checked before any Entra change; this cannot fail here.
    let store = ctx
        .policy
        .resolve_push_store(req.cluster_secret_store.as_deref())
        .map_err(Error::Invalid)?;
    let remote_key = ctx.policy.push_remote_key(&ns, &o.name_any());
    let pushed_to = format!("{store}:{remote_key}");
    let name = secret_name.to_string();
    let spec = push::spec(
        &store,
        secret_name,
        &remote_key,
        keys,
        &ctx.policy.push_refresh_interval,
    );
    let hash = push::spec_hash(&spec);
    let existing = api.get_opt(&name).await?;
    let current = existing
        .as_ref()
        .and_then(|e| e.annotations().get(push::ANN_SPEC_HASH))
        == Some(&hash);
    let obj = match existing {
        Some(e) if current => e,
        _ => {
            let mut d = DynamicObject::new(&name, &push::api_resource()).within(&ns);
            d.metadata.labels = Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                MANAGER.to_string(),
            )]));
            d.metadata.annotations = Some(BTreeMap::from([(
                push::ANN_SPEC_HASH.to_string(),
                hash.clone(),
            )]));
            d.metadata.owner_references = Some(vec![
                o.controller_owner_ref(&())
                    .expect("IAMClient has a name and uid"),
            ]);
            d.data = json!({ "spec": spec });
            let applied = ctx
                .audit
                .audited(
                    oref,
                    subj,
                    "apply_push_secret",
                    json!({ "pushSecret": name, "store": store, "remoteKey": remote_key, "keys": keys }),
                    api.patch(&name, &PatchParams::apply(MANAGER).force(), &Patch::Apply(&d)),
                )
                .await;
            match applied {
                Ok(o) => o,
                Err(e) if is_not_found(&e) => {
                    return Ok(Some(PushOutcome {
                        name,
                        pushed_to,
                        state: SyncState::Failed(format!(
                            "{}/{} {} is not installed in this cluster",
                            push::GROUP,
                            push::VERSION,
                            push::KIND
                        )),
                    }));
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    Ok(Some(PushOutcome {
        name,
        pushed_to,
        state: push::synced_since(&obj, since),
    }))
}

/// Delete this client's PushSecret if there is one. ESO then deletes the
/// OpenBao copy (`deletionPolicy: Delete`).
async fn delete_push_secret(
    o: &IAMClient,
    ctx: &Ctx,
    subj: &Subject,
    oref: &k8s_openapi::api::core::v1::ObjectReference,
    reason: &str,
) -> Result<(), Error> {
    let ns = o.namespace().unwrap_or_default();
    let name = format!("{}-entra", o.name_any());
    let api = push_api(ctx, &ns);
    let Some(existing) = api.get_opt(&name).await? else {
        return Ok(());
    };
    // Only ever delete a PushSecret this IAMClient owns.
    let owned = existing
        .owner_references()
        .iter()
        .any(|r| Some(&r.uid) == o.uid().as_ref());
    if !owned {
        return Ok(());
    }
    let res = ctx
        .audit
        .audited(
            oref,
            subj,
            "delete_push_secret",
            json!({ "pushSecret": name, "reason": reason }),
            api.delete(&name, &DeleteParams::default()),
        )
        .await;
    match res {
        Ok(_) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(e.into()),
    }
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
    s.conditions = vec![condition(prev, o, "Ready", "False", reason, msg)];
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
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
) -> Condition {
    // Keep lastTransitionTime stable unless the status actually flips.
    let since = prev
        .conditions
        .iter()
        .find(|c| c.type_ == type_ && c.status == status)
        .map(|c| c.last_transition_time.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    Condition {
        type_: type_.into(),
        status: status.into(),
        reason: reason.into(),
        message: message.chars().take(1000).collect(),
        last_transition_time: since,
        observed_generation: o.meta().generation,
    }
}

/// Why the delivered secret must be replaced now, or `None` to keep it.
///
/// `delivered` is the delivered credential's expiry as Entra reports it
/// (`None`: no delivered credential found). Rotation starts when a third of
/// the lifetime remains. A secret that outlives the approved lifetime (an admin
/// shortened `secretRotation`) is replaced at once rather than left to run.
fn rotation_reason(
    delivered: Option<Option<DateTime<Utc>>>,
    has_secret_data: bool,
    now: DateTime<Utc>,
    lifetime: ChronoDuration,
) -> Option<&'static str> {
    let Some(end) = delivered else {
        return Some("initial_or_missing");
    };
    if !has_secret_data {
        return Some("initial_or_missing");
    }
    let Some(end) = end else {
        return Some("rotation");
    };
    // Entra rounds end dates; allow a few minutes before calling it too long.
    if end > now + lifetime + ChronoDuration::minutes(5) {
        return Some("lifetime_shortened");
    }
    if now >= end - lifetime / 3 {
        return Some("rotation");
    }
    None
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
    fn rotation() {
        let now = Utc::now();
        let d90 = ChronoDuration::days(90);
        let at = |days: i64| Some(Some(now + ChronoDuration::days(days)));
        assert_eq!(
            rotation_reason(None, true, now, d90),
            Some("initial_or_missing")
        );
        assert_eq!(
            rotation_reason(at(80), false, now, d90),
            Some("initial_or_missing")
        );
        assert_eq!(
            rotation_reason(Some(None), true, now, d90),
            Some("rotation")
        );
        // Fresh secret: keep it.
        assert_eq!(rotation_reason(at(90), true, now, d90), None);
        assert_eq!(rotation_reason(at(31), true, now, d90), None);
        // A third of the lifetime (30d) left: rotate.
        assert_eq!(rotation_reason(at(30), true, now, d90), Some("rotation"));
        assert_eq!(rotation_reason(at(-1), true, now, d90), Some("rotation"));
        // Approved lifetime shortened from 90d to 3h: replace the 90d secret now.
        let h3 = ChronoDuration::hours(3);
        assert_eq!(
            rotation_reason(at(89), true, now, h3),
            Some("lifetime_shortened")
        );
        // A secret issued just now under 3h is not "too long".
        let fresh = Some(Some(now + h3 + ChronoDuration::seconds(30)));
        assert_eq!(rotation_reason(fresh, true, now, h3), None);
    }

    #[test]
    fn drift() {
        let app = Application {
            id: "o".into(),
            app_id: "a".into(),
            display_name: Some("charter-Pay".into()),
            sign_in_audience: Some("AzureADMyOrg".into()),
            group_membership_claims: Some("ApplicationGroup".into()),
            web: Some(crate::graph::Web {
                redirect_uris: vec!["https://b/cb".into(), "https://a/cb".into()],
            }),
            password_credentials: vec![],
        };
        let r = vec!["https://a/cb".to_string(), "https://b/cb".to_string()];
        assert!(diff(&app, "charter-Pay", &r, "ApplicationGroup").is_empty());
        assert_eq!(
            diff(&app, "charter-Pay", &r[..1], "None"),
            vec!["groupMembershipClaims", "web.redirectUris"]
        );
    }
}
