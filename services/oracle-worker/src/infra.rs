use std::{
    fs,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};

pub(crate) fn check_wallet(tns_admin: &str) -> Result<(), String> {
    let dir = Path::new(tns_admin);
    if !dir.is_dir() {
        return Err(format!("wallet directory missing: {tns_admin}"));
    }

    for file in ["tnsnames.ora", "sqlnet.ora", "cwallet.sso"] {
        let candidate = dir.join(file);
        if !candidate.is_file() {
            return Err(format!(
                "missing Oracle wallet artifact: {}",
                candidate.display()
            ));
        }
    }

    Ok(())
}

pub(crate) fn check_oracle_libs(ld_library_path: &str) -> Result<(), String> {
    for dir in ld_library_path
        .split(':')
        .filter(|entry| !entry.trim().is_empty())
    {
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

pub(crate) fn check_secret_file(path: &str) -> Result<(), String> {
    if Path::new(path).is_file() {
        Ok(())
    } else {
        Err(format!("missing Oracle password file: {path}"))
    }
}

pub(crate) fn check_redpanda(redpanda_bootstrap_servers: &str) -> Result<(), String> {
    let address = parse_redpanda_address(redpanda_bootstrap_servers)?;
    let socket = address
        .to_socket_addrs()
        .map_err(|error| format!("resolve Redpanda address {address}: {error}"))?
        .next()
        .ok_or_else(|| format!("no Redpanda addresses resolved for {address}"))?;
    TcpStream::connect_timeout(&socket, Duration::from_secs(2))
        .map(|_| ())
        .map_err(|error| format!("connect Redpanda {address}: {error}"))
}

pub(crate) fn parse_redpanda_address(redpanda_bootstrap_servers: &str) -> Result<String, String> {
    let trimmed = redpanda_bootstrap_servers.trim();
    if trimmed.starts_with("tls://") {
        return Err("tls:// Redpanda URLs are not supported for worker healthcheck".to_string());
    }
    let without_scheme = trimmed.strip_prefix("redpanda://").unwrap_or(trimmed);
    let authority = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| "missing Redpanda authority".to_string())?;
    if authority.is_empty() {
        return Err("missing Redpanda authority".to_string());
    }
    if authority.contains(':') {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:9092"))
    }
}

pub(crate) fn redpanda_log_authority(redpanda_url: &str) -> String {
    match parse_redpanda_address(redpanda_url) {
        Ok(authority) => authority
            .rsplit_once('@')
            .map(|(_, host)| host.to_string())
            .unwrap_or(authority),
        Err(_) => "unresolved".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_redpanda_address;

    #[test]
    fn parse_redpanda_address_adds_default_port() {
        assert_eq!(
            parse_redpanda_address("redpanda.local").unwrap(),
            "redpanda.local:9092"
        );
    }

    #[test]
    fn parse_redpanda_address_rejects_tls_urls() {
        assert!(parse_redpanda_address("tls://redpanda.local:4222").is_err());
    }
}
