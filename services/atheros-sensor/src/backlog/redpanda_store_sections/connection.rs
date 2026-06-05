use std::{
    io::Cursor,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssl_proxy::{
    config::SyncConfig,
    sync::{ScanRequest, SYNC_SCAN_REQUEST_TOPIC},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::debug;

use super::store::{
    AuthorizedWirelessNetwork, BacklogEntry, BacklogError, BacklogFailureStage, BacklogStore,
    IngestRecord,
};
use crate::publish::PublishClient;

const BACKLOG_SAVE_TOPIC: &str = "wireless.backlog.save";
const BACKLOG_LIST_TOPIC: &str = "wireless.backlog.list";
const BACKLOG_SYNCED_TOPIC: &str = "wireless.backlog.synced";
const BACKLOG_PRUNE_TOPIC: &str = "wireless.backlog.prune";
const MAC_LOOKUP_TOPIC: &str = "wireless.mac.lookup";
const AUTHORIZED_NETWORKS_TOPIC: &str = "wireless.networks.authorized";
const PROBE_FLUSH_TOPIC: &str = "wireless.probe.flush";
static NEXT_INBOX_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct RedpandaBacklog {
    publisher: Arc<dyn PublishClient>,
    sync: SyncConfig,
    request_timeout: Duration,
    request_connection_ttl: Duration,
    tls_connector: Option<TlsConnector>,
    request_connection: Arc<Mutex<Option<CachedRequestConnection>>>,
    health_status: Arc<AtomicBool>,
    connection_generation: Arc<AtomicU64>,
}

struct CachedRequestConnection {
    reader: BufReader<Box<dyn RedpandaStream>>,
    last_used: Instant,
    next_sid: u64,
}
