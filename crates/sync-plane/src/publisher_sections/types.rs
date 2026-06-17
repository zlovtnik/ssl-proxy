use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opentelemetry::{global, propagation::Injector};
use rdkafka::{
    message::{Header, OwnedHeaders},
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    runtime::RuntimeFlavor,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, field, info_span, warn, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::{
    parse_payload_ref, PublishedMessage, ScanRequest, SyncConfig, INLINE_PAYLOAD_REF_PREFIX,
    OUTBOX_PAYLOAD_REF_PREFIX, SYNC_SCAN_REQUEST_TOPIC,
};

pub const ENQUEUE_TIMEOUT_ERROR: &str = "sync publisher enqueue timed out";

#[derive(Clone, Debug)]
struct SyncPublisherConfig {
    redpanda_bootstrap_servers: Option<String>,
    connect_timeout: Duration,
    publish_timeout: Duration,
    queue_capacity: usize,
    enqueue_timeout: Duration,
    security_protocol: Option<String>,
    sasl_mechanisms: Option<String>,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
    ssl_ca_location: Option<String>,
    ssl_certificate_location: Option<String>,
    ssl_key_location: Option<String>,
    inline_payload_max_bytes: usize,
    outbox_dir: PathBuf,
    publish_spool_dir: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct SyncPublisherHealth {
    last_attempt_at: Option<String>,
    last_publish_at: Option<String>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyncPublisherHealthSnapshot {
    pub configured: bool,
    pub auth_enabled: bool,
    pub tls_enabled: bool,
    pub inline_payload_max_bytes: usize,
    pub outbox_dir: String,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub queue_available: usize,
    pub spool_dir: String,
    pub spool_pending: usize,
    pub spooled_total: u64,
    pub enqueue_timeouts_total: u64,
    pub last_attempt_at: Option<String>,
    pub last_publish_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
struct SyncPublisherCounters {
    spooled_total: AtomicU64,
    enqueue_timeouts_total: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct SyncPublisher {
    config: SyncPublisherConfig,
    published: Arc<Mutex<Vec<PublishedMessage>>>,
    health: Arc<Mutex<SyncPublisherHealth>>,
    counters: Arc<SyncPublisherCounters>,
    publish_tx: Arc<Mutex<Option<PublishQueueSender>>>,
    publish_task: Arc<Mutex<Option<PublishTaskHandle>>>,
}

struct PublishQueueMessage {
    topic: String,
    payload: String,
    response_tx: Option<oneshot::Sender<Result<(), String>>>,
}
type PublishQueueSender = mpsc::Sender<PublishQueueMessage>;
type PublishTaskHandle = JoinHandle<()>;

enum EnqueueError {
    Timeout,
    Closed,
}

#[derive(Deserialize, Serialize)]
struct PublishSpoolEnvelope {
    topic: String,
    payload: String,
    created_at: String,
}
