mod worker;

use async_nats::jetstream::{
    self,
    consumer::{self, pull::Config as PullConsumerConfig},
    stream::Stream,
};
use futures::StreamExt;
use std::{
    env, fs,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::{Duration, Instant},
};

const SERVICE_NAME: &str = "oracle-worker";
const HEARTBEAT_INTERVAL_SECS: u64 = 300;
const DEFAULT_AUDIT_STREAM_NAME: &str = "AUDIT_STREAM";
const DEFAULT_SYNC_LOAD_SUBJECT: &str = "sync.oracle.load";
const DEFAULT_SYNC_RESULT_SUBJECT: &str = "sync.oracle.result";
const DEFAULT_SYNC_LOAD_CONSUMER: &str = "oracle-worker-load";

struct HealthcheckConfig {
    sync_nats_url: String,
    tns_admin: String,
    ld_library_path: String,
    oracle_pass_file: String,
}

impl HealthcheckConfig {
    fn load() -> Result<Self, String> {
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
struct RunConfig {
    sync_nats_url: String,
    audit_stream_name: String,
    load_subject: String,
    result_subject: String,
    load_consumer: String,
}

impl RunConfig {
    fn load() -> Result<Self, String> {
        Ok(Self {
            sync_nats_url: required_env("SYNC_NATS_URL")?,
            audit_stream_name: env_or_default("AUDIT_STREAM_NAME", DEFAULT_AUDIT_STREAM_NAME),
            load_subject: env_or_default("SYNC_LOAD_SUBJECT", DEFAULT_SYNC_LOAD_SUBJECT),
            result_subject: env_or_default("SYNC_RESULT_SUBJECT", DEFAULT_SYNC_RESULT_SUBJECT),
            load_consumer: env_or_default("SYNC_LOAD_CONSUMER", DEFAULT_SYNC_LOAD_CONSUMER),
        })
    }
}

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "run".to_string());
    println!("service={SERVICE_NAME} event=process_start mode={mode}");
    let outcome = match mode.as_str() {
        "run" => run(),
        "healthcheck" => healthcheck("healthcheck"),
        other => Err(format!("unknown mode: {other}. expected run or healthcheck")),
    };

    if let Err(error) = outcome {
        eprintln!(
            "service={SERVICE_NAME} event=fatal status=error mode={mode} error=\"{}\"",
            escape_for_log(&error)
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let started = Instant::now();
    healthcheck("run")?;
    println!("service={SERVICE_NAME} event=ready mode=run status=ok");
    let config = RunConfig::load()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("initialize tokio runtime: {error}"))?;

    runtime.block_on(run_loop(config, started))
}

async fn run_loop(config: RunConfig, started: Instant) -> Result<(), String> {
    let client = async_nats::connect(config.sync_nats_url.clone())
        .await
        .map_err(|error| format!("connect NATS {}: {error}", config.sync_nats_url))?;
    let jetstream = jetstream::new(client);
    let stream = jetstream
        .get_stream(config.audit_stream_name.clone())
        .await
        .map_err(|error| {
            format!(
                "get JetStream stream {}: {error}",
                config.audit_stream_name
            )
        })?;
    let consumer = ensure_load_consumer(&stream, &config).await?;
    let mut messages = consumer
        .messages()
        .await
        .map_err(|error| format!("open pull consumer message stream: {error}"))?;

    let mut last_heartbeat = Instant::now();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            signal = &mut shutdown => {
                let signal = signal?;
                println!("service={SERVICE_NAME} event=signal_received signal={signal}");
                break;
            }
            _ = heartbeat.tick() => {
                println!(
                    "service={SERVICE_NAME} event=heartbeat uptime_s={} interval_s={HEARTBEAT_INTERVAL_SECS} since_last_heartbeat_s={}",
                    started.elapsed().as_secs(),
                    last_heartbeat.elapsed().as_secs(),
                );
                last_heartbeat = Instant::now();
                tokio::task::spawn_blocking(|| healthcheck("run"))
                    .await
                    .map_err(|error| format!("healthcheck task panicked: {error}"))??;
            }
            next_message = messages.next() => {
                match next_message {
                    Some(Ok(message)) => {
                        handle_load_message(&jetstream, &config, message).await?;
                    }
                    Some(Err(error)) => {
                        return Err(format!("consume sync.oracle.load message: {error}"));
                    }
                    None => {
                        return Err("sync.oracle.load consumer stream ended unexpectedly".to_string());
                    }
                }
            }
        }
    }

    println!(
        "service={SERVICE_NAME} event=shutdown status=graceful uptime_s={}",
        started.elapsed().as_secs()
    );
    Ok(())
}

async fn ensure_load_consumer(
    stream: &Stream,
    config: &RunConfig,
) -> Result<jetstream::consumer::PullConsumer, String> {
    stream
        .get_or_create_consumer(
            config.load_consumer.as_str(),
            PullConsumerConfig {
                durable_name: Some(config.load_consumer.clone()),
                filter_subject: config.load_subject.clone(),
                ack_policy: consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            format!(
                "get/create pull consumer {} on stream {} (subject {}): {error}",
                config.load_consumer, config.audit_stream_name, config.load_subject
            )
        })
}

async fn handle_load_message(
    jetstream: &jetstream::Context,
    config: &RunConfig,
    message: jetstream::Message,
) -> Result<(), String> {
    let load = match serde_json::from_slice::<worker::OracleLoad>(&message.payload) {
        Ok(load) => load,
        Err(error) => {
            eprintln!(
                "service={SERVICE_NAME} event=worker_load status=error classification=poison payload_bytes={} error=\"{}\"",
                message.payload.len(),
                escape_for_log(&format!("deserialize OracleLoad payload: {error}"))
            );
            message
                .ack()
                .await
                .map_err(|ack_error| format!("ack poison message: {ack_error}"))?;
            return Ok(());
        }
    };

    let result = worker::handle_load(load);
    let batch_id = result.batch_id.clone();
    let status = result.status.clone();

    let payload = serde_json::to_vec(&result)
        .map_err(|error| format!("serialize OracleResult for batch {batch_id}: {error}"))?;
    let publish_ack = jetstream
        .publish(config.result_subject.clone(), payload.into())
        .await
        .map_err(|error| {
            format!(
                "publish sync.oracle.result for batch {batch_id} to {}: {error}",
                config.result_subject
            )
        })?;
    publish_ack
        .await
        .map_err(|error| format!("await publish ack for batch {batch_id}: {error}"))?;

    message
        .ack()
        .await
        .map_err(|error| format!("ack sync.oracle.load message for batch {batch_id}: {error}"))?;
    println!(
        "service={SERVICE_NAME} event=worker_load status=ok batch_id={batch_id} result_status={status}"
    );

    Ok(())
}

async fn wait_for_shutdown_signal() -> Result<&'static str, String> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| format!("register SIGTERM handler: {error}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| format!("wait for SIGINT: {error}"))?;
                Ok("SIGINT")
            }
            _ = terminate.recv() => Ok("SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(|error| format!("wait for SIGINT: {error}"))?;
        Ok("SIGINT")
    }
}

fn healthcheck(mode: &str) -> Result<(), String> {
    let started = Instant::now();
    println!("service={SERVICE_NAME} event=healthcheck status=start mode={mode}");
    let config = HealthcheckConfig::load().map_err(|error| {
        eprintln!(
            "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step=load_config error=\"{}\"",
            started.elapsed().as_millis(),
            escape_for_log(&error)
        );
        error
    })?;
    println!(
        "service={SERVICE_NAME} event=config_summary mode={mode} nats_authority={} wallet_path={} ld_library_path={} oracle_pass_file={}",
        nats_log_authority(&config.sync_nats_url),
        config.tns_admin,
        config.ld_library_path,
        config.oracle_pass_file,
    );

    run_healthcheck_step("check_wallet", || check_wallet(&config.tns_admin)).map_err(|error| {
        eprintln!(
            "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step=check_wallet error=\"{}\"",
            started.elapsed().as_millis(),
            escape_for_log(&error)
        );
        error
    })?;
    run_healthcheck_step("check_oracle_libs", || {
        check_oracle_libs(&config.ld_library_path)
    })
    .map_err(|error| {
        eprintln!(
            "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step=check_oracle_libs error=\"{}\"",
            started.elapsed().as_millis(),
            escape_for_log(&error)
        );
        error
    })?;
    run_healthcheck_step("check_secret_file", || {
        check_secret_file(&config.oracle_pass_file)
    })
    .map_err(|error| {
        eprintln!(
            "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step=check_secret_file error=\"{}\"",
            started.elapsed().as_millis(),
            escape_for_log(&error)
        );
        error
    })?;
    run_healthcheck_step("check_nats", || check_nats(&config.sync_nats_url)).map_err(|error| {
        eprintln!(
            "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step=check_nats error=\"{}\"",
            started.elapsed().as_millis(),
            escape_for_log(&error)
        );
        error
    })?;
    println!(
        "service={SERVICE_NAME} event=healthcheck status=ok mode={mode} duration_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}

fn run_healthcheck_step<F>(step: &str, f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let started = Instant::now();
    println!("service={SERVICE_NAME} event=healthcheck_step status=start step={step}");
    match f() {
        Ok(()) => {
            println!(
                "service={SERVICE_NAME} event=healthcheck_step status=ok step={step} duration_ms={}",
                started.elapsed().as_millis()
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn required_env(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("missing required env: {name}")),
    }
}

fn env_or_default(name: &str, default: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_string(),
    }
}

fn check_wallet(tns_admin: &str) -> Result<(), String> {
    let dir = Path::new(tns_admin);
    if !dir.is_dir() {
        return Err(format!("wallet directory missing: {tns_admin}"));
    }

    for file in ["tnsnames.ora", "sqlnet.ora", "cwallet.sso"] {
        let candidate = dir.join(file);
        if !candidate.is_file() {
            return Err(format!("missing Oracle wallet artifact: {}", candidate.display()));
        }
    }

    Ok(())
}

fn check_oracle_libs(ld_library_path: &str) -> Result<(), String> {
    for dir in ld_library_path.split(':').filter(|entry| !entry.trim().is_empty()) {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        let entries = fs::read_dir(path).map_err(|error| error.to_string())?;
        if entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .any(|name| name.starts_with("libclntsh"))
        {
            return Ok(());
        }
    }

    Err(format!(
        "no libclntsh* shared library found under LD_LIBRARY_PATH={ld_library_path}"
    ))
}

fn check_secret_file(path: &str) -> Result<(), String> {
    if Path::new(path).is_file() {
        Ok(())
    } else {
        Err(format!("missing Oracle password file: {path}"))
    }
}

fn check_nats(nats_url: &str) -> Result<(), String> {
    let address = parse_nats_address(nats_url)?;
    let socket = address
        .to_socket_addrs()
        .map_err(|error| format!("resolve NATS address {address}: {error}"))?
        .next()
        .ok_or_else(|| format!("no NATS addresses resolved for {address}"))?;
    TcpStream::connect_timeout(&socket, Duration::from_secs(2))
        .map(|_| ())
        .map_err(|error| format!("connect NATS {address}: {error}"))
}

fn parse_nats_address(nats_url: &str) -> Result<String, String> {
    let trimmed = nats_url.trim();
    if trimmed.starts_with("tls://") {
        return Err("tls:// NATS URLs are not supported for worker healthcheck".to_string());
    }
    let without_scheme = trimmed.strip_prefix("nats://").unwrap_or(trimmed);
    let authority = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| "missing NATS authority".to_string())?;
    if authority.is_empty() {
        return Err("missing NATS authority".to_string());
    }
    if authority.contains(':') {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:4222"))
    }
}

fn nats_log_authority(nats_url: &str) -> String {
    match parse_nats_address(nats_url) {
        Ok(authority) => authority
            .rsplit_once('@')
            .map(|(_, host)| host.to_string())
            .unwrap_or(authority),
        Err(_) => "unresolved".to_string(),
    }
}

fn escape_for_log(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' | '\r' | '\t' => escaped.push(' '),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{env_or_default, parse_nats_address};

    #[test]
    fn parse_nats_address_adds_default_port() {
        assert_eq!(
            parse_nats_address("nats://nats.local").unwrap(),
            "nats.local:4222"
        );
    }

    #[test]
    fn parse_nats_address_rejects_tls_urls() {
        assert!(parse_nats_address("tls://nats.local:4222").is_err());
    }

    #[test]
    fn env_or_default_uses_fallback_for_blank_values() {
        let key = format!("OW_TEST_FALLBACK_{}", std::process::id());
        std::env::set_var(&key, "");
        assert_eq!(env_or_default(&key, "fallback"), "fallback");
        std::env::remove_var(&key);
    }
}
