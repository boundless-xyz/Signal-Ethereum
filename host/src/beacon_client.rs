// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ethereum_consensus::{
    Fork, phase0::SignedBeaconBlockHeader, primitives::Root, serde::as_str,
    types::mainnet::BeaconBlock,
};
use http::StatusCode;
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use middleware::RateLimitMiddleware;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use std::result::Result as StdResult;
use tracing::warn;
use url::Url;
use z_core::{ChainReader, Checkpoint, ConsensusState, mainnet::BeaconState};

/// Errors returned by the [BeaconClient].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not parse URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON request middleware failed: {0}")]
    Middleware(#[from] reqwest_middleware::Error),
    #[error("version field does not match data version")]
    VersionMismatch,
    #[error("Ssz deserialize error: {0}")]
    SszDeserialize(#[from] ssz_rs::DeserializeError),
}

/// Alias for Results returned by client methods.
pub type Result<T> = StdResult<T, Error>;

/// Response returned by the `get_block_header` API.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockHeaderResponse {
    pub root: Root,
    pub canonical: bool,
    pub header: SignedBeaconBlockHeader,
}

/// Response returned by the `get_block_header` API.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub message: BeaconBlock,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointResponse {
    pub root: Root,
    #[serde(with = "as_str")]
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizedCheckpointResponse {
    pub previous_justified: CheckpointResponse,
    pub current_justified: CheckpointResponse,
    pub finalized: CheckpointResponse,
}

/// Wrapper returned by the API calls.
#[derive(Debug, Serialize, Deserialize)]
struct Response<T> {
    data: T,
    #[serde(flatten)]
    meta: HashMap<String, serde_json::Value>,
}

/// Wrapper returned by the API calls that includes a version.
#[derive(Serialize, Deserialize)]
struct VersionedResponse<T> {
    version: Fork,
    #[serde(flatten)]
    inner: Response<T>,
}

/// Simple beacon API client for the `mainnet` preset that can query headers and blocks.
#[derive(Clone)]
pub struct BeaconClient {
    http: ClientWithMiddleware,
    endpoint: Url,
}

mod middleware {
    use governor::{
        Quota, RateLimiter, clock::DefaultClock, state::InMemoryState, state::NotKeyed,
    };
    use http::Extensions;
    use reqwest::{Request, Response};
    use reqwest_middleware::{Middleware, Next, Result};
    use std::num::NonZeroU32;
    use std::sync::Arc;

    pub struct RateLimitMiddleware {
        limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    }

    impl RateLimitMiddleware {
        /// Creates a new rate limiter middleware.
        pub fn new(requests_per_second: u32) -> Self {
            let rps = NonZeroU32::new(requests_per_second)
                .expect("requests_per_second should be non-zero");
            Self {
                limiter: Arc::new(RateLimiter::direct(Quota::per_second(rps))),
            }
        }
    }

    #[async_trait::async_trait]
    impl Middleware for RateLimitMiddleware {
        async fn handle(
            &self,
            req: Request,
            extensions: &mut Extensions,
            next: Next<'_>,
        ) -> Result<Response> {
            // This will asynchronously wait until the request is allowed based on the quota.
            self.limiter.until_ready().await;
            // Proceed with the request
            next.run(req, extensions).await
        }
    }
}

pub struct BeaconClientBuilder {
    endpoint: Url,
    inner: ClientBuilder,
    cache_mw: Option<Cache<CACacheManager>>,
    rate_limit_mw: Option<RateLimitMiddleware>,
}

impl BeaconClientBuilder {
    pub fn new(endpoint: Url) -> Self {
        let client = reqwest::Client::new();
        Self {
            endpoint,
            inner: ClientBuilder::new(client),
            cache_mw: None,
            rate_limit_mw: None,
        }
    }

    pub fn with_cache(mut self, cache_dir: impl Into<PathBuf>) -> Self {
        let manager = CACacheManager {
            path: cache_dir.into(),
        };
        let cache = Cache(HttpCache {
            mode: CacheMode::ForceCache,
            manager,
            options: HttpCacheOptions::default(),
        });

        self.cache_mw = Some(cache);
        self
    }

    pub fn with_rate_limit(mut self, requests_per_second: u32) -> Self {
        if requests_per_second == 0 {
            self.rate_limit_mw = None;
            return self;
        }
        let rate_limit = RateLimitMiddleware::new(requests_per_second);

        self.rate_limit_mw = Some(rate_limit);
        self
    }

    pub fn build(mut self) -> BeaconClient {
        if let Some(cache_mw) = self.cache_mw {
            self.inner = self.inner.with(cache_mw);
        }
        if let Some(rate_limit_mw) = self.rate_limit_mw {
            self.inner = self.inner.with(rate_limit_mw);
        }

        BeaconClient {
            http: self.inner.build(),
            endpoint: self.endpoint,
        }
    }
}

impl BeaconClient {
    pub fn builder(endpoint: Url) -> BeaconClientBuilder {
        BeaconClientBuilder::new(endpoint)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let target = self.endpoint.join(path)?;
        let resp = self.http.get(target).send().await?;
        let value = resp.error_for_status()?.json().await?;
        Ok(value)
    }

    /// Retrieves block details for the given block ID.
    ///
    /// Block ID can be 'head', 'genesis', 'finalized', <slot>, or <root>.
    #[tracing::instrument(skip(self), fields(block_id = %block_id))]
    pub async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> Result<Option<BlockHeaderResponse>> {
        let path = format!("eth/v1/beacon/headers/{block_id}");
        match self.get_json::<Response<_>>(&path).await {
            Ok(resp) => Ok(Some(resp.data)),
            Err(Error::Http(err)) => match err.status() {
                Some(StatusCode::NOT_FOUND) => Ok(None),
                _ => Err(err.into()),
            },
            Err(err) => Err(err),
        }
    }

    /// Retrieves block details for given block id.
    ///
    /// Block ID can be 'head', 'genesis', 'finalized', <slot>, or <root>.
    #[tracing::instrument(skip(self), fields(block_id = %block_id))]
    pub async fn get_block(&self, block_id: impl Display) -> Result<Option<BeaconBlock>> {
        let path = format!("eth/v2/beacon/blocks/{block_id}");
        match self.get_json::<Response<BlockResponse>>(&path).await {
            Ok(resp) => Ok(Some(resp.data.message)),
            Err(Error::Http(err)) => match err.status() {
                Some(StatusCode::NOT_FOUND) => Ok(None),
                _ => Err(err.into()),
            },
            Err(err) => Err(err),
        }
    }

    #[tracing::instrument(skip(self), fields(state_id = %state_id))]
    pub async fn get_beacon_state(&self, state_id: impl Display) -> Result<BeaconState> {
        let path = format!("eth/v2/debug/beacon/states/{state_id}");
        let result: VersionedResponse<BeaconState> = self.get_json(&path).await?;
        if result.version.to_string() != result.inner.data.version().to_string() {
            warn!(
                "FORK: {:?}, Version mismatch: {} != {}",
                result.inner.data.fork(),
                result.version,
                result.inner.data.version()
            );
            return Err(Error::VersionMismatch);
        }
        Ok(result.inner.data)
    }

    #[tracing::instrument(skip(self), fields(state_id = %state_id))]
    pub async fn get_finality_checkpoints(
        &self,
        state_id: impl Display,
    ) -> Result<FinalizedCheckpointResponse> {
        let path = format!("eth/v1/beacon/states/{state_id}/finality_checkpoints");
        let result: Response<FinalizedCheckpointResponse> = self.get_json(&path).await?;

        Ok(result.data)
    }
}

impl From<CheckpointResponse> for Checkpoint {
    fn from(response: CheckpointResponse) -> Self {
        Self {
            epoch: response.epoch,
            root: response.root,
        }
    }
}

impl ChainReader for BeaconClient {
    async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> anyhow::Result<Option<SignedBeaconBlockHeader>> {
        let resp = self.get_block_header(block_id).await?;
        Ok(resp.map(|resp| resp.header))
    }

    async fn get_block(&self, block_id: impl Display) -> anyhow::Result<Option<BeaconBlock>> {
        Ok(self.get_block(block_id).await?)
    }

    async fn get_consensus_state(&self, state_id: impl Display) -> anyhow::Result<ConsensusState> {
        let resp = self.get_finality_checkpoints(state_id).await?;
        Ok(ConsensusState {
            previous_justified_checkpoint: resp.previous_justified.into(),
            current_justified_checkpoint: resp.current_justified.into(),
            finalized_checkpoint: resp.finalized.into(),
        })
    }
}
