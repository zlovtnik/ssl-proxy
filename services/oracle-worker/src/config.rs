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
}

impl RunConfig {
    pub(crate) fn load() -> Result<Self, String> {
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
        })
    }
}
