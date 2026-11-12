//! Reconcile loop: IAMClient -> Entra app registration + service principal +
//! client secret + Kubernetes Secret carrying credentials and Dex config.

use crate::crd::{Condition, IAMClient, IAMClientStatus};
use crate::graph::{Graph, GraphError};
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
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const FINALIZER: &str = "iam.rbc.example/entra-cleanup";
const MANAGER: &str = "entra-controller";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("graph: {0}")]
    Graph(#[from] GraphError),
    #[error("kube: {0}")]
    Kube(#[from] kube::Error),
    #[error("finalizer: {0}")]
    Finalizer(#[source] Box<kube::runtime::finalizer::Error<Error>>),
    #[error("invalid spec: {0}")]
    Invalid(String),
}

pub struct Ctx {
    pub client: Client,
    pub graph: Graph,
    /// Enforced prefix for every registration this controller owns, e.g. `iamaas-`.
    pub name_prefix: String,
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
                    tracing::info!(object = %obj.name, ns = ?obj.namespace, "reconciled")
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
    // Graph throttles with 429; a flat backoff is fine for a scaffold.
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

async fn apply(o: &IAMClient, ctx: &Ctx) -> Result<Action, Error> {
    let ns = o.namespace().unwrap_or_default();
    let name = o.name_any();
    let spec = &o.spec;
    let status = o.status.clone().unwrap_or_default();
    let lifetime = parse_duration(&spec.secret_rotation)?;

    // Entra only ever sees Dex's callback when Dex fronts the client.
    let entra_redirects: Vec<String> = match &spec.dex {
        Some(d) => vec![format!("{}/callback", d.issuer_url.trim_end_matches('/'))],
        None => spec.redirect_uris.clone(),
    };
    for uri in &entra_redirects {
        validate_redirect(uri)?;
    }

    // 1. App registration (idempotent upsert keyed on uniqueName).
    let uname = unique_name(&ctx.name_prefix, o);
    let body = json!({
        "displayName": format!("{}{}", ctx.name_prefix, spec.display_name),
        "signInAudience": "AzureADMyOrg",
        "web": { "redirectUris": entra_redirects },
        "groupMembershipClaims": if spec.groups.is_empty() { "None" } else { "ApplicationGroup" },
        "tags": ["iamaas", format!("k8s:{ns}/{name}")],
        "notes": format!("Managed by entra-controller from IAMClient {ns}/{name}. Do not edit by hand."),
    });
    let app = ctx.graph.upsert_application(&uname, &body).await?;

    // 2. Service principal and human owners.
    let sp_id = ctx.graph.ensure_service_principal(&app.app_id).await?;
    for owner in &spec.owners {
        ctx.graph.add_owner(&app.id, owner).await?;
    }

    // 3. Client secret, rotated when a third of its lifetime remains.
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
    let secret_name = format!("{name}-entra");
    let existing = secrets.get_opt(&secret_name).await?;
    let existing_data = existing
        .as_ref()
        .and_then(|s| s.data.clone())
        .unwrap_or_default();
    let expires_at = status
        .secret_expires_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    let now = Utc::now();
    let rotate_at = expires_at.map(|e| e - lifetime / 3);
    let needs_secret = status.secret_key_id.is_none()
        || !existing_data.contains_key("client-secret")
        || rotate_at.is_none_or(|r| now >= r);

    let (client_secret, key_id, expires_at) = if needs_secret {
        let pw = ctx
            .graph
            .add_password(
                &app.id,
                &format!("iamaas {}", now.format("%Y-%m-%d")),
                now + lifetime,
            )
            .await?;
        tracing::info!(%ns, %name, key_id = %pw.key_id, "issued new client secret");
        (pw.secret_text, pw.key_id, pw.end_date_time)
    } else {
        let s = String::from_utf8(existing_data["client-secret"].0.clone()).unwrap_or_default();
        (
            s,
            status.secret_key_id.clone().unwrap_or_default(),
            expires_at.unwrap_or(now),
        )
    };

    // 4. Deliver. TODO: swap for an OpenBao sink (KV v2 write) behind a trait.
    let dex_client_secret = existing_data
        .get("dex-client-secret")
        .map(|b| String::from_utf8_lossy(&b.0).into_owned())
        .unwrap_or_else(random_secret);
    let mut data = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        data.insert(k.to_string(), ByteString(v.into_bytes()));
    };
    put("tenant-id", ctx.graph.tenant_id.clone());
    put("client-id", app.app_id.clone());
    put("client-secret", client_secret.clone());
    put(
        "issuer",
        format!(
            "https://login.microsoftonline.com/{}/v2.0",
            ctx.graph.tenant_id
        ),
    );
    if let Some(dex) = &spec.dex {
        put("dex-client-secret", dex_client_secret.clone());
        put(
            "dex-config.yaml",
            dex_config(
                o,
                &dex.issuer_url,
                &ctx.graph.tenant_id,
                &app.app_id,
                &client_secret,
                &dex_client_secret,
            ),
        );
    }
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(ns.clone()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                MANAGER.to_string(),
            )])),
            owner_references: Some(vec![o.controller_owner_ref(&()).unwrap()]),
            ..Default::default()
        },
        type_: Some("Opaque".into()),
        data: Some(data),
        ..Default::default()
    };
    secrets
        .patch(
            &secret_name,
            &PatchParams::apply(MANAGER).force(),
            &Patch::Apply(&secret),
        )
        .await?;

    // Only revoke the old secret after the new one is delivered.
    if needs_secret && let Some(old) = status.secret_key_id.as_deref().filter(|k| *k != key_id) {
        ctx.graph.remove_password(&app.id, old).await?;
    }

    // 5. Status.
    let new_status = IAMClientStatus {
        app_id: Some(app.app_id),
        object_id: Some(app.id),
        service_principal_id: Some(sp_id),
        secret_key_id: Some(key_id),
        secret_expires_at: Some(expires_at.to_rfc3339()),
        secret_name: Some(secret_name),
        observed_generation: o.meta().generation,
        conditions: vec![ready(
            o,
            &status,
            "Reconciled",
            "App registration, service principal and secret are in place",
        )],
    };
    let api: Api<IAMClient> = Api::namespaced(ctx.client.clone(), &ns);
    api.patch_status(
        &name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "status": new_status })),
    )
    .await?;

    // Wake up for the next rotation, or hourly to correct drift.
    let until_rotation = (expires_at - lifetime / 3 - Utc::now())
        .to_std()
        .unwrap_or_default();
    Ok(Action::requeue(
        until_rotation.clamp(Duration::from_secs(60), Duration::from_secs(3600)),
    ))
}

async fn cleanup(o: &IAMClient, ctx: &Ctx) -> Result<Action, Error> {
    // The Kubernetes Secret goes with the owner reference.
    let uname = unique_name(&ctx.name_prefix, o);
    ctx.graph.delete_application(&uname).await?;
    tracing::info!(unique_name = %uname, "deleted app registration (soft-deleted in Entra for 30 days)");
    Ok(Action::await_change())
}

fn ready(o: &IAMClient, prev: &IAMClientStatus, reason: &str, message: &str) -> Condition {
    // Keep lastTransitionTime stable unless the status actually flips.
    let since = prev
        .conditions
        .iter()
        .find(|c| c.type_ == "Ready" && c.status == "True")
        .map(|c| c.last_transition_time.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    Condition {
        type_: "Ready".into(),
        status: "True".into(),
        reason: reason.into(),
        message: message.into(),
        last_transition_time: since,
        observed_generation: o.meta().generation,
    }
}

fn validate_redirect(uri: &str) -> Result<(), Error> {
    let ok = uri.starts_with("https://")
        || uri.starts_with("http://localhost")
        || uri.starts_with("http://127.0.0.1");
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!("redirect URI must be https: {uri}")))
    }
}

/// `90d`, `720h`, `30m`.
pub fn parse_duration(s: &str) -> Result<ChronoDuration, Error> {
    let bad = || {
        Error::Invalid(format!(
            "secretRotation must look like 90d or 720h, got {s:?}"
        ))
    };
    let (n, unit) = s.split_at(s.len().checked_sub(1).ok_or_else(bad)?);
    let n: i64 = n.parse().map_err(|_| bad())?;
    let d = match unit {
        "d" => ChronoDuration::days(n),
        "h" => ChronoDuration::hours(n),
        "m" => ChronoDuration::minutes(n),
        _ => return Err(bad()),
    };
    // Entra caps secrets at 2 years; most tenants enforce less via policy.
    if d < ChronoDuration::hours(1) || d > ChronoDuration::days(730) {
        return Err(bad());
    }
    Ok(d)
}

fn random_secret() -> String {
    let mut buf = [0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Dex fragment: the Microsoft connector (Dex -> Entra) and the static client
/// (team app -> Dex). A Dex config renderer merges fragments per issuer.
fn dex_config(
    o: &IAMClient,
    issuer: &str,
    tenant: &str,
    app_id: &str,
    entra_secret: &str,
    dex_secret: &str,
) -> String {
    let issuer = issuer.trim_end_matches('/');
    let v = json!({
        "connectors": [{
            "type": "microsoft",
            "id": "entra",
            "name": "RBC Entra ID",
            "config": {
                "clientID": app_id,
                "clientSecret": entra_secret,
                "redirectURI": format!("{issuer}/callback"),
                "tenant": tenant,
                "groups": o.spec.groups,
                "onlySecurityGroups": true,
            }
        }],
        "staticClients": [{
            "id": o.name_any(),
            "name": o.spec.display_name,
            "secret": dex_secret,
            "redirectURIs": o.spec.redirect_uris,
        }]
    });
    serde_yaml::to_string(&v).unwrap_or_default()
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
    fn redirects() {
        assert!(validate_redirect("https://app.example.com/cb").is_ok());
        assert!(validate_redirect("http://localhost:8080/cb").is_ok());
        assert!(validate_redirect("http://app.example.com/cb").is_err());
    }
}
