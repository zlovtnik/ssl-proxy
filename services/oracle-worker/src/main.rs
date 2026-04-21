mod worker;

use std::{
    env,
    fs,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    thread,
    time::Duration,
};

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "run".to_string());
    let outcome = match mode.as_str() {
        "run" => run(),
        "healthcheck" => healthcheck(),
        other => Err(format!("unknown mode: {other}. expected run or healthcheck")),
    };

    if let Err(error) = outcome {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    healthcheck()?;
    println!("oracle-worker ready");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn healthcheck() -> Result<(), String> {
    let sync_nats_url = required_env("SYNC_NATS_URL")?;
    let tns_admin = required_env("TNS_ADMIN")?;
    let ld_library_path = required_env("LD_LIBRARY_PATH")?;
    let _oracle_conn = required_env("ORACLE_CONN")?;
    let _oracle_user = required_env("ORACLE_USER")?;
    let oracle_pass_file = required_env("ORACLE_PASS_FILE")?;

    check_wallet(&tns_admin)?;
    check_oracle_libs(&ld_library_path)?;
    check_secret_file(&oracle_pass_file)?;
    check_nats(&sync_nats_url)?;
    Ok(())
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
