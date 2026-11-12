//! Minimal Microsoft Graph client: token acquisition plus the handful of
//! application / service principal calls the controller needs.
//!
//! Authentication prefers workload identity federation (the projected service
//! account token that the Azure Workload Identity webhook mounts at
//! `AZURE_FEDERATED_TOKEN_FILE`). `AZURE_CLIENT_SECRET` is supported for local
//! development only.

use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
const SCOPE: &str = "https://graph.microsoft.com/.default";

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("graph {status}: {body}")]
    Api { status: StatusCode, body: String },
    #[error("config: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GraphError>;

enum Credential {
    /// Workload identity federation: exchange a projected SA token for a Graph token.
    Federated { token_file: String },
    /// Local development only.
    Secret { secret: String },
}

struct CachedToken {
    token: String,
    expires: Instant,
}

pub struct Graph {
    http: Client,
    pub tenant_id: String,
    client_id: String,
    authority: String,
    cred: Credential,
    cache: Mutex<Option<CachedToken>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub app_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Password {
    pub key_id: String,
    pub secret_text: String,
    pub end_date_time: DateTime<Utc>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl Graph {
    pub fn from_env() -> Result<Self> {
        let var =
            |k: &str| std::env::var(k).map_err(|_| GraphError::Config(format!("{k} not set")));
        let tenant_id = var("AZURE_TENANT_ID")?;
        let client_id = var("AZURE_CLIENT_ID")?;
        let authority = std::env::var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|_| "https://login.microsoftonline.com/".into());
        let cred = if let Ok(token_file) = std::env::var("AZURE_FEDERATED_TOKEN_FILE") {
            Credential::Federated { token_file }
        } else if let Ok(secret) = std::env::var("AZURE_CLIENT_SECRET") {
            tracing::warn!("using AZURE_CLIENT_SECRET; use workload identity in real clusters");
            Credential::Secret { secret }
        } else {
            return Err(GraphError::Config(
                "set AZURE_FEDERATED_TOKEN_FILE (workload identity) or AZURE_CLIENT_SECRET".into(),
            ));
        };
        Ok(Self {
            http: Client::builder().timeout(Duration::from_secs(30)).build()?,
            tenant_id,
            client_id,
            authority,
            cred,
            cache: Mutex::new(None),
        })
    }

    async fn token(&self) -> Result<String> {
        let mut cache = self.cache.lock().await;
        if let Some(c) = cache.as_ref()
            && c.expires > Instant::now() + Duration::from_secs(300)
        {
            return Ok(c.token.clone());
        }
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.authority.trim_end_matches('/'),
            self.tenant_id
        );
        let mut form = vec![
            ("client_id", self.client_id.clone()),
            ("scope", SCOPE.to_string()),
            ("grant_type", "client_credentials".to_string()),
        ];
        match &self.cred {
            Credential::Federated { token_file } => {
                // Re-read every time: kubelet rotates the projected token.
                let assertion = tokio::fs::read_to_string(token_file).await?;
                form.push((
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ));
                form.push(("client_assertion", assertion.trim().to_string()));
            }
            Credential::Secret { secret } => form.push(("client_secret", secret.clone())),
        }
        let resp = self.http.post(url).form(&form).send().await?;
        let resp = check(resp).await?;
        let t: TokenResponse = resp.json().await?;
        let token = t.access_token.clone();
        *cache = Some(CachedToken {
            token: t.access_token,
            expires: Instant::now() + Duration::from_secs(t.expires_in),
        });
        Ok(token)
    }

    async fn req(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self
            .http
            .request(method, format!("{GRAPH}{path}"))
            .bearer_auth(self.token().await?))
    }

    /// Idempotent create-or-update keyed on `uniqueName`, using Graph's upsert
    /// (`PATCH /applications(uniqueName='..')` with `Prefer: create-if-missing`).
    pub async fn upsert_application(&self, unique_name: &str, body: &Value) -> Result<Application> {
        let path = format!("/applications(uniqueName='{}')", odata_escape(unique_name));
        let resp = self
            .req(reqwest::Method::PATCH, &path)
            .await?
            .header("Prefer", "create-if-missing")
            .json(body)
            .send()
            .await?;
        check(resp).await?;
        let resp = self
            .req(reqwest::Method::GET, &format!("{path}?$select=id,appId"))
            .await?
            .send()
            .await?;
        Ok(check(resp).await?.json().await?)
    }

    /// Delete by uniqueName. Missing is success. Entra soft-deletes for 30 days.
    pub async fn delete_application(&self, unique_name: &str) -> Result<()> {
        let path = format!("/applications(uniqueName='{}')", odata_escape(unique_name));
        let resp = self
            .req(reqwest::Method::DELETE, &path)
            .await?
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        check(resp).await.map(|_| ())
    }

    /// Return the service principal for `app_id`, creating it if missing.
    pub async fn ensure_service_principal(&self, app_id: &str) -> Result<String> {
        let path = format!(
            "/servicePrincipals(appId='{}')?$select=id",
            odata_escape(app_id)
        );
        let resp = self.req(reqwest::Method::GET, &path).await?.send().await?;
        if resp.status() != StatusCode::NOT_FOUND {
            let v: Value = check(resp).await?.json().await?;
            return id_of(&v);
        }
        let resp = self
            .req(reqwest::Method::POST, "/servicePrincipals")
            .await?
            .json(&json!({ "appId": app_id }))
            .send()
            .await?;
        let v: Value = check(resp).await?.json().await?;
        id_of(&v)
    }

    /// Add a directory object (user or SP) as owner. Already-an-owner is success.
    pub async fn add_owner(&self, app_object_id: &str, owner_id: &str) -> Result<()> {
        let resp = self
            .req(
                reqwest::Method::POST,
                &format!("/applications/{app_object_id}/owners/$ref"),
            )
            .await?
            .json(&json!({ "@odata.id": format!("{GRAPH}/directoryObjects/{owner_id}") }))
            .send()
            .await?;
        if resp.status() == StatusCode::BAD_REQUEST {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("already exist") {
                return Ok(());
            }
            return Err(GraphError::Api {
                status: StatusCode::BAD_REQUEST,
                body,
            });
        }
        check(resp).await.map(|_| ())
    }

    pub async fn add_password(
        &self,
        app_object_id: &str,
        display_name: &str,
        end: DateTime<Utc>,
    ) -> Result<Password> {
        let resp = self
            .req(
                reqwest::Method::POST,
                &format!("/applications/{app_object_id}/addPassword"),
            )
            .await?
            .json(&json!({ "passwordCredential": {
                "displayName": display_name,
                "endDateTime": end.to_rfc3339(),
            }}))
            .send()
            .await?;
        Ok(check(resp).await?.json().await?)
    }

    pub async fn remove_password(&self, app_object_id: &str, key_id: &str) -> Result<()> {
        let resp = self
            .req(
                reqwest::Method::POST,
                &format!("/applications/{app_object_id}/removePassword"),
            )
            .await?
            .json(&json!({ "keyId": key_id }))
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        check(resp).await.map(|_| ())
    }
}

async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(GraphError::Api { status, body })
    }
}

fn id_of(v: &Value) -> Result<String> {
    v["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| GraphError::Config("graph response missing id".into()))
}

fn odata_escape(s: &str) -> String {
    s.replace('\'', "''")
}
