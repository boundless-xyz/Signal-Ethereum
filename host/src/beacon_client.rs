// Copyright 2024 RISC Zero, Inc.
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

// TODO(ec2): Maybe we just redefine this so we can remove the beacon_api_client dependency altogether
use beacon_api_client::FinalityCheckpoints;

use ethereum_consensus::{
    deneb::{Epoch, Slot},
    phase0::SignedBeaconBlockHeader,
    primitives::Root,
    serde::as_str,
    types::mainnet::BeaconBlock,
    Fork,
};
use futures::{Stream, StreamExt};
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    IntoUrl,
};
use reqwest_eventsource::{Event, EventSource};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{self, Display};
use tracing::{info, warn};
use url::Url;

use z_core::mainnet::BeaconState;
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
}

/// Response returned by the `get_block_header` API.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockHeaderResponse {
    pub root: Root,
    pub canonical: bool,
    pub header: SignedBeaconBlockHeader,
}

/// Response returned by the `get_block_header` API.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockResponse {
    pub message: BeaconBlock,
}

/// Wrapper returned by the API calls.
#[derive(Serialize, Deserialize)]
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
pub struct BeaconClient {
    http: ClientWithMiddleware,
    endpoint: Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTopic {
    Head,
    Block,
    FinalizedCheckpoint,
}

impl fmt::Display for EventTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventTopic::Head => write!(f, "head"),
            EventTopic::Block => write!(f, "block"),
            EventTopic::FinalizedCheckpoint => write!(f, "finalized_checkpoint"),
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Clone)]
pub enum EventKind {
    Head(SseHead),
    Block(SseBlock),
    FinalizedCheckpoint(SseFinalizedCheckpoint),
}

impl EventKind {
    pub fn from_sse_bytes(event: &str, data: &str) -> Result<Self, String> {
        match event {
            "block" => Ok(EventKind::Block(
                serde_json::from_str(data).map_err(|e| format!("Block: {:?}", e))?,
            )),
            "finalized_checkpoint" => Ok(EventKind::FinalizedCheckpoint(
                serde_json::from_str(data).map_err(|e| format!("Finalized Checkpoint: {:?}", e))?,
            )),
            "head" => Ok(EventKind::Head(
                serde_json::from_str(data).map_err(|e| format!("Head: {:?}", e))?,
            )),
            _ => Err("Could not parse event tag".to_string()),
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseFinalizedCheckpoint {
    pub block: Root,
    pub state: Root,
    #[serde(with = "as_str")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseHead {
    #[serde(with = "as_str")]
    pub slot: Slot,
    pub block: Root,
    pub state: Root,
    pub current_duty_dependent_root: Root,
    pub previous_duty_dependent_root: Root,
    pub epoch_transition: bool,
    pub execution_optimistic: bool,
}
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseBlock {
    #[serde(with = "as_str")]
    pub slot: Slot,
    pub block: Root,
    pub execution_optimistic: bool,
}

impl BeaconClient {
    /// Creates a new beacon endpoint API client.
    pub fn new<U: IntoUrl>(endpoint: U) -> Result<Self, Error> {
        let client = reqwest::Client::new();
        Ok(Self {
            http: client.into(),
            endpoint: endpoint.into_url()?,
        })
    }

    /// Creates a new beacon endpoint API client with caching.
    pub fn new_with_cache<U: IntoUrl>(endpoint: U, cache_dir: &str) -> Result<Self, Error> {
        let client = reqwest::Client::new();
        let manager = CACacheManager {
            path: cache_dir.into(),
        };
        let cache = Cache(HttpCache {
            mode: CacheMode::ForceCache,
            manager,
            options: HttpCacheOptions::default(),
        });
        let client_with_middleware = ClientBuilder::new(client).with(cache).build();

        Ok(Self {
            http: client_with_middleware,
            endpoint: endpoint.into_url()?,
        })
    }

    async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let target = self.endpoint.join(path)?;
        let resp = self.http.get(target).send().await?;
        let value = resp.error_for_status()?.json().await?;
        Ok(value)
    }

    async fn http_get_ssz(&self, path: &str) -> Result<Vec<u8>, Error> {
        let target = self.endpoint.join(path)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/octet-stream"),
        );
        let resp = self.http.get(target).headers(headers).send().await?;
        let value = resp
            .error_for_status()?
            .bytes()
            .await?
            .into_iter()
            .collect();
        Ok(value)
    }

    /// Retrieves block details for given block id.
    #[tracing::instrument(skip(self), fields(block_id = %block_id))]
    pub async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> Result<SignedBeaconBlockHeader, Error> {
        let path = format!("eth/v1/beacon/headers/{block_id}");
        let result: Response<GetBlockHeaderResponse> = self.http_get(&path).await?;
        Ok(result.data.header)
    }

    /// Retrieves block details for given block id.
    #[tracing::instrument(skip(self), fields(block_id = %block_id))]
    pub async fn get_block(&self, block_id: impl Display) -> Result<BeaconBlock, Error> {
        let path = format!("eth/v2/beacon/blocks/{block_id}");
        let result: Response<GetBlockResponse> = self.http_get(&path).await?;
        Ok(result.data.message)
    }

    #[tracing::instrument(skip(self), fields(state_id = %state_id))]
    pub async fn get_beacon_state(&self, state_id: impl Display) -> Result<BeaconState, Error> {
        let path = format!("eth/v2/debug/beacon/states/{state_id}");
        let result: VersionedResponse<BeaconState> = self.http_get(&path).await?;
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
    /// TODO(ec2): This is borked... It just keeps getting json instead of octet-stream
    pub async fn get_beacon_state_ssz(&self, state_id: impl Display) -> Result<Vec<u8>, Error> {
        let path = format!("eth/v2/debug/beacon/states/{state_id}");

        let result: Vec<u8> = self.http_get_ssz(&path).await?;
        Ok(result)
    }

    #[tracing::instrument(skip(self), fields(state_id = %state_id))]
    pub async fn get_finality_checkpoints(
        &self,
        state_id: impl Display,
    ) -> Result<FinalityCheckpoints, Error> {
        let path = format!("eth/v1/beacon/states/{state_id}/finality_checkpoints");
        let result: Response<FinalityCheckpoints> = self.http_get(&path).await?;

        Ok(result.data)
    }

    /// `GET events?topics`
    pub async fn get_events(
        &self,
        topic: &[EventTopic],
    ) -> Result<impl Stream<Item = Result<EventKind, String>>, String> {
        let mut path = format!("eth/v1/events");

        let topic_string = topic
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        path = format!("{path}?topics={}", topic_string.as_str());

        info!("Get Events: {path}");

        let mut es = EventSource::get(self.endpoint.join(&path).unwrap());
        // If we don't await `Event::Open` here, then the consumer
        // will not get any Message events until they start awaiting the stream.
        // This is a way to register the stream with the sse server before
        // message events start getting emitted.
        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => break,
                Err(err) => return Err(format!("{:?}", err)),
                // This should never happen as we are guaranteed to get the
                // Open event before any message starts coming through.
                Ok(Event::Message(_)) => continue,
            }
        }
        Ok(Box::pin(es.filter_map(|event| async move {
            match event {
                Ok(Event::Open) => None,
                Ok(Event::Message(message)) => {
                    Some(EventKind::from_sse_bytes(&message.event, &message.data))
                }
                Err(err) => Some(Err(format!("{:?}", err))),
            }
        })))
    }
}
