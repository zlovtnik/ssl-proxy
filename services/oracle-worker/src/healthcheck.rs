use std::time::Instant;

use crate::config::HealthcheckConfig;
use crate::infra::{
    check_redpanda, check_oracle_libs, check_secret_file, check_wallet, redpanda_log_authority,
};
use crate::log::escape_for_log;
use crate::{worker, SERVICE_NAME};

pub(crate) fn healthcheck(mode: &str) -> Result<(), String> {
    let started = Instant::now();
    println!("service={SERVICE_NAME} event=healthcheck status=start mode={mode}");
    let config = load_config(mode, started)?;
    println!(
        "service={SERVICE_NAME} event=config_summary mode={mode} redpanda_authority={} wallet_path={} ld_library_path={} oracle_pass_file={}",
        redpanda_log_authority(&config.redpanda_bootstrap_servers),
        config.tns_admin,
        config.ld_library_path,
        config.oracle_pass_file,
    );

    run_step(mode, started, "check_wallet", || {
        check_wallet(&config.tns_admin)
    })?;
    run_step(mode, started, "check_oracle_libs", || {
        check_oracle_libs(&config.ld_library_path)
    })?;
    run_step(mode, started, "check_secret_file", || {
        check_secret_file(&config.oracle_pass_file)
    })?;
    run_step(mode, started, "check_oracle_connection", || {
        worker::check_oracle_connection_from_env()
    })?;
    run_step(mode, started, "check_redpanda", || {
        check_redpanda(&config.redpanda_bootstrap_servers)
    })?;
    println!(
        "service={SERVICE_NAME} event=healthcheck status=ok mode={mode} duration_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}

fn load_config(mode: &str, started: Instant) -> Result<HealthcheckConfig, String> {
    HealthcheckConfig::load().map_err(|error| {
        log_healthcheck_error(mode, started, "load_config", &error);
        error
    })
}

fn run_step<F>(mode: &str, started: Instant, step: &str, f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    run_healthcheck_step(step, f).map_err(|error| {
        log_healthcheck_error(mode, started, step, &error);
        error
    })
}

pub(crate) fn run_healthcheck_step<F>(step: &str, f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let started = Instant::now();
    println!("service={SERVICE_NAME} event=healthcheck_step status=start step={step}");
    f()?;
    println!(
        "service={SERVICE_NAME} event=healthcheck_step status=ok step={step} duration_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}

fn log_healthcheck_error(mode: &str, started: Instant, step: &str, error: &str) {
    eprintln!(
        "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step={step} error=\"{}\"",
        started.elapsed().as_millis(),
        escape_for_log(error)
    );
}
