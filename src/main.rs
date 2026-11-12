mod controller;
mod crd;
mod graph;

use kube::CustomResourceExt;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `entra-controller crd` prints the CRD YAML for `kubectl apply`.
    if std::env::args().nth(1).as_deref() == Some("crd") {
        print!("{}", serde_yaml::to_string(&crd::IAMClient::crd())?);
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let ctx = Arc::new(controller::Ctx {
        client: kube::Client::try_default().await?,
        graph: graph::Graph::from_env()?,
        name_prefix: std::env::var("NAME_PREFIX").unwrap_or_else(|_| "iamaas-".into()),
    });
    tracing::info!(prefix = %ctx.name_prefix, "starting entra-controller");
    controller::run(ctx).await;
    Ok(())
}
