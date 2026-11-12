mod audit;
mod controller;
mod crd;
mod graph;
mod policy;

use kube::CustomResourceExt;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `entra-controller crd` prints the CRD YAML for `kubectl apply`.
    // `entra-controller spec-hash <file>` prints the hash an approver signs off.
    match std::env::args().nth(1).as_deref() {
        Some("crd") => {
            print!("{}", serde_norway::to_string(&crd::IAMClient::crd())?);
            return Ok(());
        }
        Some("spec-hash") => {
            let path = std::env::args()
                .nth(2)
                .ok_or_else(|| anyhow::anyhow!("usage: spec-hash <iamclient.yaml>"))?;
            let obj: crd::IAMClient = serde_norway::from_str(&std::fs::read_to_string(path)?)?;
            println!("{}", policy::spec_hash(&obj.spec));
            return Ok(());
        }
        _ => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let client = kube::Client::try_default().await?;
    let graph = graph::Graph::from_env()?;
    let policy = policy::Policy::from_env();
    let grace_hours = std::env::var("ROTATION_GRACE_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    tracing::info!(?policy, grace_hours, "starting entra-controller");
    let ctx = Arc::new(controller::Ctx {
        audit: audit::Auditor::new(client.clone(), graph.client_id.clone()),
        client,
        graph,
        policy,
        rotation_grace: chrono::Duration::hours(grace_hours),
    });
    controller::run(ctx).await;
    Ok(())
}
