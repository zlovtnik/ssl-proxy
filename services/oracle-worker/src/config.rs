use crate::env::{env_or_default, env_or_default_usize, required_env};
use crate::{
    DEFAULT_AUDIT_STREAM_NAME, DEFAULT_ORACLE_WORKER_PARALLELISM, DEFAULT_SYNC_LOAD_CONSUMER,
    DEFAULT_SYNC_LOAD_SUBJECT, DEFAULT_SYNC_RESULT_SUBJECT,
};

pub(crate) struct HealthcheckConfig {
    pub(crate) sync_nats_url: String,
    pub(crate) tns_admin: String,
    pub(crate) ld_library_path: String,
    pub(crate) oracle_pass_file: String,
}

impl HealthcheckConfig {
    pub(crate) fn load() -> Result<Self, String> {
        let sync_nats_url = required_env("SYNC_NATS_URL")?;
        let tns_admin = required_env("TNS_ADMIN")?;
        let ld_library_path = required_env("LD_LIBRARY_PATH")?;
        let _oracle_conn = required_env("ORACLE_CONN")?;
        let _oracle_user = required_env("ORACLE_USER")?;
        let oracle_pass_file = required_env("ORACLE_PASS_FILE")?;
        Ok(Self {
            sync_nats_url,
            tns_admin,
            ld_library_path,
            oracle_pass_file,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RunConfig {
    pub(crate) sync_nats_url: String,
    pub(crate) audit_stream_name: String,
    pub(crate) load_subject: String,
    pub(crate) result_subject: String,
    pub(crate) load_consumer: String,
    pub(crate) oracle_worker_parallelism: usize,
}

impl RunConfig {
    pub(crate) fn load() -> Result<Self, String> {
        Ok(Self {
            sync_nats_url: required_env("SYNC_NATS_URL")?,
            audit_stream_name: env_or_default("AUDIT_STREAM_NAME", DEFAULT_AUDIT_STREAM_NAME),
            load_subject: env_or_default("SYNC_LOAD_SUBJECT", DEFAULT_SYNC_LOAD_SUBJECT),
            result_subject: env_or_default("SYNC_RESULT_SUBJECT", DEFAULT_SYNC_RESULT_SUBJECT),
            load_consumer: env_or_default("SYNC_LOAD_CONSUMER", DEFAULT_SYNC_LOAD_CONSUMER),
            oracle_worker_parallelism: env_or_default_usize(
                "ORACLE_WORKER_PARALLELISM",
                DEFAULT_ORACLE_WORKER_PARALLELISM,
            ),
        })
    }
}
