use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{error::Get401Error, models::PublicKeyData};

const DEFAULT_HOST: &str = "https://app.get401.com";

struct CachedKey {
    data: PublicKeyData,
    /// Wall-clock time at which the cache entry expires.
    expires_at: SystemTime,
}

/// Wire format of the `/v1/apps/auth/public-key` response.
#[derive(Deserialize)]
struct ApiPublicKeyResponse {
    public_key: String,
    algorithm: String,
    expires_at: u64,
}

/// Configuration for [`Get401Client`].
#[derive(Debug, Clone)]
pub struct Get401ClientConfig {
    pub app_id: String,
    pub origin: String,
    pub host: String,
}

/// Low-level HTTP client for the get401 backend.
///
/// Handles public-key retrieval with automatic expiry-based caching.
/// Wrap it in an [`Arc`] and share between handlers — it is designed for
/// concurrent use.
///
/// # Example
/// ```rust
/// use std::sync::Arc;
/// use get401::{Get401Client, TokenVerifier};
///
/// let client = Arc::new(Get401Client::new("app-id", "https://myapp.com"));
/// let verifier = TokenVerifier::new(Arc::clone(&client));
/// ```
#[derive(Debug)]
pub struct Get401Client {
    config: Get401ClientConfig,
    cache: RwLock<Option<CachedKey>>,
    http: reqwest::Client,
}

impl Get401Client {
    /// Create a client using the default get401 host (`https://app.get401.com`).
    pub fn new(app_id: impl Into<String>, origin: impl Into<String>) -> Self {
        Self::with_host(app_id, origin, DEFAULT_HOST)
    }

    /// Create a client with a custom host (useful for self-hosted deployments or tests).
    pub fn with_host(
        app_id: impl Into<String>,
        origin: impl Into<String>,
        host: impl Into<String>,
    ) -> Self {
        let host = host.into();
        let host = host.trim_end_matches('/').to_string();

        Self {
            config: Get401ClientConfig {
                app_id: app_id.into(),
                origin: origin.into(),
                host,
            },
            cache: RwLock::new(None),
            http: reqwest::Client::new(),
        }
    }

    /// Return the current public key, fetching from the backend when the cache
    /// has expired or does not exist yet.
    pub async fn get_public_key(&self) -> Result<PublicKeyData, Get401Error> {
        // Fast path: check with a read lock.
        {
            let cache = self.cache.read().await;
            if let Some(c) = cache.as_ref() {
                if SystemTime::now() < c.expires_at {
                    return Ok(c.data.clone());
                }
            }
        }

        // Slow path: acquire write lock and re-check (double-checked locking).
        let mut cache = self.cache.write().await;
        if let Some(c) = cache.as_ref() {
            if SystemTime::now() < c.expires_at {
                return Ok(c.data.clone());
            }
        }

        let data = self.fetch_from_api().await?;
        let expires_at =
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.expires_at);
        *cache = Some(CachedKey { data: data.clone(), expires_at });
        Ok(data)
    }

    /// Force a cache refresh and return the new public key.
    pub async fn refresh_public_key(&self) -> Result<PublicKeyData, Get401Error> {
        let data = self.fetch_from_api().await?;
        let expires_at =
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.expires_at);
        *self.cache.write().await = Some(CachedKey { data: data.clone(), expires_at });
        Ok(data)
    }

    async fn fetch_from_api(&self) -> Result<PublicKeyData, Get401Error> {
        let url = format!("{}/v1/apps/auth/public-key", self.config.host);

        let response = self
            .http
            .get(&url)
            .header("X-App-Id", &self.config.app_id)
            .header("Origin", &self.config.origin)
            .send()
            .await
            .map_err(|e| Get401Error::PublicKeyFetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Get401Error::PublicKeyFetch(format!(
                "Backend returned HTTP {}",
                response.status()
            )));
        }

        let api: ApiPublicKeyResponse = response
            .json()
            .await
            .map_err(|e| Get401Error::PublicKeyFetch(format!("Failed to parse response: {e}")))?;

        Ok(PublicKeyData {
            public_key: api.public_key,
            algorithm: api.algorithm,
            expires_at: api.expires_at,
        })
    }
}
