use crate::env::{env_or_default, env_or_default_usize, required_env};
use crate::{
    DEFAULT_AUDIT_STREAM_NAME, DEFAULT_ORACLE_WORKER_PARALLELISM, DEFAULT_SYNC_LOAD_CONSUMER,
    DEFAULT_SYNC_LOAD_TOPIC, DEFAULT_SYNC_RESULT_TOPIC,
};

pub(crate) struct HealthcheckConfig {
    pub(crate) redpanda_bootstrap_servers: String,
    pub(crate) tns_admin: String,
    pub(crate) ld_library_path: String,
    pub(crate) oracle_pass_file: String,
}

impl HealthcheckConfig {
    pub(crate) fn load() -> Result<Self, String> {
        let redpanda_bootstrap_servers = required_env("SYNC_REDPANDA_BOOTSTRAP_SERVERS")?;
        let tns_admin = required_env("TNS_ADMIN")?;
        let ld_library_path = required_env("LD_LIBRARY_PATH")?;
        let _oracle_conn = required_env("ORACLE_CONN")?;
        let _oracle_user = required_env("ORACLE_USER")?;
        let oracle_pass_file = required_env("ORACLE_PASS_FILE")?;
        Ok(Self {
            redpanda_bootstrap_servers,
            tns_admin,
            ld_library_path,
            oracle_pass_file,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RunConfig {
    pub(crate) redpanda_bootstrap_servers: String,
    pub(crate) audit_stream_name: String,
    pub(crate) load_topic: String,
    pub(crate) result_topic: String,
    pub(crate) load_consumer: String,
    pub(crate) oracle_worker_parallelism: usize,
    pub(crate) window_duration_secs: u64,
    pub(crate) window_max_messages: usize,
    pub(crate) oracle_statement_timeout_secs: u64,
    pub(crate) metrics_port: u16,
}

fn non_zero_u64(value: u64, default: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value
    }
}

fn non_zero_usize(value: usize, default: usize) -> usize {
    if value == 0 {
        default
    } else {
        value
    }
}

impl RunConfig {
    pub(crate) fn load() -> Result<Self, String> {
        let metrics_port = env_or_default("ORACLE_WORKER_METRICS_PORT", "9464")
            .parse::<u16>()
            .unwrap_or(9464);
        Ok(Self {
            redpanda_bootstrap_servers: required_env("SYNC_REDPANDA_BOOTSTRAP_SERVERS")?,
            audit_stream_name: env_or_default("AUDIT_STREAM_NAME", DEFAULT_AUDIT_STREAM_NAME),
            load_topic: env_or_default("SYNC_LOAD_TOPIC", DEFAULT_SYNC_LOAD_TOPIC),
            result_topic: env_or_default("SYNC_RESULT_TOPIC", DEFAULT_SYNC_RESULT_TOPIC),
            load_consumer: env_or_default("SYNC_LOAD_CONSUMER", DEFAULT_SYNC_LOAD_CONSUMER),
            oracle_worker_parallelism: env_or_default_usize(
                "ORACLE_WORKER_PARALLELISM",
                DEFAULT_ORACLE_WORKER_PARALLELISM,
            ),
            window_duration_secs: non_zero_u64(
                env_or_default("ORACLE_WINDOW_DURATION_SECS", "15")
                    .parse()
                    .unwrap_or(15),
                15,
            ),
            window_max_messages: non_zero_usize(
                env_or_default_usize("ORACLE_WINDOW_MAX_MESSAGES", 200),
                200,
            ),
            oracle_statement_timeout_secs: non_zero_u64(
                env_or_default("ORACLE_STATEMENT_TIMEOUT_SECS", "30")
                    .parse()
                    .unwrap_or(30),
                30,
            ),
            metrics_port,
        })
    }
}
