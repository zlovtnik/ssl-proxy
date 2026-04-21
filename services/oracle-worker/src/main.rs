mod worker;

use std::{
    env,
    fs,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    thread,
    time::{Duration, Instant},
};

const SERVICE_NAME: &str = "oracle-worker";
const HEARTBEAT_INTERVAL_SECS: u64 = 300;

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
    let mut last_heartbeat = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));
        if last_heartbeat.elapsed() >= Duration::from_secs(HEARTBEAT_INTERVAL_SECS) {
            println!(
                "service={SERVICE_NAME} event=heartbeat uptime_s={} interval_s={HEARTBEAT_INTERVAL_SECS}",
                started.elapsed().as_secs()
            );
            last_heartbeat = Instant::now();
        }
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
    run_healthcheck_step("check_oracle_libs", || check_oracle_libs(&config.ld_library_path)).map_err(|error| {
        eprintln!(
            "service={SERVICE_NAME} event=healthcheck status=error mode={mode} duration_ms={} failed_step=check_oracle_libs error=\"{}\"",
            started.elapsed().as_millis(),
            escape_for_log(&error)
        );
        error
    })?;
    run_healthcheck_step("check_secret_file", || check_secret_file(&config.oracle_pass_file)).map_err(|error| {
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
        Err(error) => {
            eprintln!(
                "service={SERVICE_NAME} event=healthcheck_step status=error step={step} duration_ms={} error=\"{}\"",
                started.elapsed().as_millis(),
                escape_for_log(&error)
            );
            Err(error)
        }
    }
}

fn required_env(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("missing required env: {name}")),
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
        let mut entries = fs::read_dir(path).map_err(|error| error.to_string())?;
        if entries.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .map(|name| name.starts_with("libclntsh"))
                .unwrap_or(false)
        }) {
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
