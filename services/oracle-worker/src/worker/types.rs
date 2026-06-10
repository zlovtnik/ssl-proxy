use oracle::Connection;
use r2d2_oracle::OracleConnectionManager;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleLoad {
    pub job_id: String,
    pub batch_id: String,
    pub batch_no: Option<i32>,
    pub stream_name: String,
    pub payload_ref: Option<String>,
    pub cursor_start: Option<String>,
    pub cursor_end: Option<String>,
    pub attempt: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleResult {
    pub job_id: String,
    pub batch_id: String,
    pub status: String,
    pub row_count: i32,
    pub checksum: String,
    pub retryable: bool,
    pub error_class: String,
    pub error_text: String,
    pub finished_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleErrorClass {
    Retryable,
    Permanent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkTarget {
    ProxyEvents,
    WirelessAuditFrames,
    WirelessBandwidth,
    WirelessRogueAp,
    WirelessDeauthFlood,
    WirelessSignalAnomaly,
    WirelessPmfAttack,
    WirelessClientInventory,
    WirelessProbeRequests,
}

pub enum OracleConnection {
    Direct(Connection),
    Pooled(r2d2::PooledConnection<OracleConnectionManager>),
}

impl std::ops::Deref for OracleConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        match self {
            OracleConnection::Direct(ref conn) => conn,
            OracleConnection::Pooled(ref conn) => conn.deref(),
        }
    }
}
