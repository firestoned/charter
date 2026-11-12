//! Minimal Microsoft Graph client: token acquisition plus the handful of
//! application / service principal calls the controller needs.
//!
//! Authentication is workload identity federation: the projected service
//! account token that the Azure Workload Identity webhook mounts at
//! `AZURE_FEDERATED_TOKEN_FILE` is exchanged for a Graph token. There is no
//! stored credential. `AZURE_CLIENT_SECRET` works only when
//! `ALLOW_CLIENT_SECRET_AUTH=true`, for local development.
//!
//! Secrets (tokens, client secrets) are held in `SecretString`, which redacts
//! `Debug` output and zeroizes memory on drop.

use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
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
    Federated { token_file: String },
    Secret { secret: SecretString },
}

struct CachedToken {
    token: SecretString,
    expires: Instant,
}

pub struct Graph {
    http: Client,
    pub tenant_id: String,
    pub client_id: String,
    authority: String,
    cred: Credential,
    cache: Mutex<Option<CachedToken>>,
    self_oid: Mutex<Option<String>>,
}

/// The fields of an application the controller manages and checks for drift.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub app_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub sign_in_audience: Option<String>,
    #[serde(default)]
    pub group_membership_claims: Option<String>,
    #[serde(default)]
    pub web: Option<Web>,
    #[serde(default)]
    pub password_credentials: Vec<PasswordCredential>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Web {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordCredential {
    pub key_id: String,
    pub end_date_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Password {
    pub key_id: String,
    pub secret_text: SecretString,
    pub end_date_time: DateTime<Utc>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretString,
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
        } else if std::env::var("ALLOW_CLIENT_SECRET_AUTH").as_deref() == Ok("true") {
            let secret = var("AZURE_CLIENT_SECRET")?;
            tracing::warn!("client secret auth enabled; this is for local development only");
            Credential::Secret {
                secret: secret.into(),
            }
        } else {
            return Err(GraphError::Config(
                "workload identity required: AZURE_FEDERATED_TOKEN_FILE is not set".into(),
            ));
        };
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .https_only(true)
                .build()?,
            tenant_id,
            client_id,
            authority,
            cred,
            cache: Mutex::new(None),
            self_oid: Mutex::new(None),
        })
    }

    async fn token(&self) -> Result<SecretString> {
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
        let mut form: Vec<(&str, String)> = vec![
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
            Credential::Secret { secret } => {
                form.push(("client_secret", secret.expose_secret().to_string()))
            }
        }
        let resp = self.http.post(url).form(&form).send().await?;
        let t: TokenResponse = check(resp).await?.json().await?;
        let token = t.access_token.clone();
        *cache = Some(CachedToken {
            token: t.access_token,
            expires: Instant::now() + Duration::from_secs(t.expires_in),
        });
        Ok(token)
    }

    /// Object ID of the controller's own service principal, from the token's
    /// `oid` claim. Used so owner reconciliation never removes the controller.
    pub async fn self_object_id(&self) -> Result<String> {
        if let Some(id) = self.self_oid.lock().await.clone() {
            return Ok(id);
        }
        let token = self.token().await?;
        let payload = token
            .expose_secret()
            .split('.')
            .nth(1)
            .ok_or_else(|| GraphError::Config("malformed access token".into()))?
            .to_string();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .map_err(|e| GraphError::Config(format!("token payload: {e}")))?;
        let v: Value = serde_json::from_slice(&bytes)
            .map_err(|e| GraphError::Config(format!("token payload: {e}")))?;
        let oid = v["oid"]
            .as_str()
            .ok_or_else(|| GraphError::Config("token has no oid claim".into()))?
            .to_string();
        *self.self_oid.lock().await = Some(oid.clone());
        Ok(oid)
    }

    async fn req(&self, method: Method, path: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self
            .http
            .request(method, format!("{GRAPH}{path}"))
            .bearer_auth(self.token().await?.expose_secret()))
    }

    fn app_path(unique_name: &str) -> String {
        format!("/applications(uniqueName='{}')", odata_escape(unique_name))
    }

    /// Current state of the app, or None if it does not exist.
    pub async fn get_application(&self, unique_name: &str) -> Result<Option<Application>> {
        let path = format!(
            "{}?$select=id,appId,displayName,signInAudience,groupMembershipClaims,web,passwordCredentials",
            Self::app_path(unique_name)
        );
        let resp = self.req(Method::GET, &path).await?.send().await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(check(resp).await?.json().await?))
    }

    /// Idempotent create-or-update keyed on `uniqueName`
    /// (`PATCH /applications(uniqueName='..')` with `Prefer: create-if-missing`).
    pub async fn upsert_application(&self, unique_name: &str, body: &Value) -> Result<Application> {
        let resp = self
            .req(Method::PATCH, &Self::app_path(unique_name))
            .await?
            .header("Prefer", "create-if-missing")
            .json(body)
            .send()
            .await?;
        check(resp).await?;
        self.get_application(unique_name)
            .await?
            .ok_or_else(|| GraphError::Config("application missing right after upsert".into()))
    }

    /// Delete by uniqueName. Missing is success. Entra soft-deletes for 30 days.
    pub async fn delete_application(&self, unique_name: &str) -> Result<()> {
        let resp = self
            .req(Method::DELETE, &Self::app_path(unique_name))
            .await?
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        check(resp).await.map(|_| ())
    }

    pub async fn get_service_principal(&self, app_id: &str) -> Result<Option<String>> {
        let path = format!(
            "/servicePrincipals(appId='{}')?$select=id",
            odata_escape(app_id)
        );
        let resp = self.req(Method::GET, &path).await?.send().await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let v: Value = check(resp).await?.json().await?;
        id_of(&v).map(Some)
    }

    pub async fn create_service_principal(&self, app_id: &str) -> Result<String> {
        let resp = self
            .req(Method::POST, "/servicePrincipals")
            .await?
            .json(&json!({ "appId": app_id }))
            .send()
            .await?;
        let v: Value = check(resp).await?.json().await?;
        id_of(&v)
    }

    pub async fn list_owners(&self, app_object_id: &str) -> Result<Vec<String>> {
        let resp = self
            .req(
                Method::GET,
                &format!("/applications/{app_object_id}/owners?$select=id"),
            )
            .await?
            .send()
            .await?;
        let v: Value = check(resp).await?.json().await?;
        Ok(v["value"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|o| o["id"].as_str().map(str::to_owned))
            .collect())
    }

    pub async fn add_owner(&self, app_object_id: &str, owner_id: &str) -> Result<()> {
        let resp = self
            .req(
                Method::POST,
                &format!("/applications/{app_object_id}/owners/$ref"),
            )
            .await?
            .json(&json!({ "@odata.id": format!("{GRAPH}/directoryObjects/{owner_id}") }))
            .send()
            .await?;
        check(resp).await.map(|_| ())
    }

    pub async fn remove_owner(&self, app_object_id: &str, owner_id: &str) -> Result<()> {
        let resp = self
            .req(
                Method::DELETE,
                &format!("/applications/{app_object_id}/owners/{owner_id}/$ref"),
            )
            .await?
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
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
                Method::POST,
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
                Method::POST,
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
        // Graph error bodies carry codes and messages, never credentials.
        let body: String = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(2000)
            .collect();
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
