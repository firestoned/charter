// Copyright (c) 2026 Erick Bourgeois, charter
// SPDX-License-Identifier: Apache-2.0

mod audit;
mod controller;
mod crd;
mod graph;
mod policy;
mod push;

use kube::CustomResourceExt;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `charter-iam crd` prints the CRD YAML for `kubectl apply`.
    if std::env::args().nth(1).as_deref() == Some("crd") {
        print!("{}", serde_norway::to_string(&crd::IAMClient::crd())?);
        return Ok(());
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
    tracing::info!(?policy, grace_hours, "starting charter-iam");
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
