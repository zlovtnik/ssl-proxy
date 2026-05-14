use std::{fs, sync::Arc, time::Duration};

use r2d2::Pool;
use r2d2_oracle::OracleConnectionManager;

use crate::config::RunConfig;
use crate::env::{env_or_default, required_env};
use crate::log::error_chain;
use crate::SERVICE_NAME;

pub(crate) fn build_oracle_pool(
    config: &RunConfig,
) -> Result<Arc<Pool<OracleConnectionManager>>, String> {
    let connect_string = required_env("ORACLE_CONN")?;
    let user = required_env("ORACLE_USER")?;
    let password_file = required_env("ORACLE_PASS_FILE")?;
    let password = fs::read_to_string(&password_file)
        .map_err(|error| format!("read Oracle password file {password_file}: {error}"))?;
    let password = password.trim_end_matches(['\r', '\n']);
    let pool_timeout_secs = env_or_default("ORACLE_POOL_TIMEOUT_SECS", "30")
        .parse()
        .unwrap_or(30);
    let manager = OracleConnectionManager::new(&user, password, &connect_string);
    println!(
        "service={SERVICE_NAME} event=pool_build_start max_size={}",
        config.oracle_worker_parallelism
    );
    let pool = r2d2::Pool::builder()
        .max_size(config.oracle_worker_parallelism as u32)
        .min_idle(Some(0))
        .connection_timeout(Duration::from_secs(pool_timeout_secs))
        .build(manager)
        .map_err(|error| format!("create Oracle connection pool: {}", error_chain(&error)))?;
    println!(
        "service={SERVICE_NAME} event=pool_build_ok max_size={}",
        config.oracle_worker_parallelism
    );
    println!(
        "service={SERVICE_NAME} event=pool_config max_size={} timeout_secs={}",
        config.oracle_worker_parallelism, pool_timeout_secs
    );
    Ok(Arc::new(pool))
}
