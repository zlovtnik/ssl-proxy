fn request_transport_unsupported(
    operation: &'static str,
    redpanda_bootstrap_servers: &str,
) -> Option<BacklogError> {
    let trimmed = redpanda_bootstrap_servers.trim();
    let without_scheme = trimmed
        .strip_prefix("tls://")
        .or_else(|| trimmed.strip_prefix("redpanda://"))
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.contains(',') {
        return Some(unsupported_request_transport_error(
            operation,
            redpanda_bootstrap_servers,
        ));
    }

    let port = redpanda_port(host_port).unwrap_or(9092);
    if port == 9092 || port == 9093 || port == 19092 {
        return Some(unsupported_request_transport_error(
            operation,
            redpanda_bootstrap_servers,
        ));
    }

    None
}

pub fn inline_request_reply_transport_supported(redpanda_bootstrap_servers: &str) -> bool {
    request_transport_unsupported("inline_request_reply", redpanda_bootstrap_servers).is_none()
}

fn unsupported_request_transport_error(
    operation: &'static str,
    redpanda_bootstrap_servers: &str,
) -> BacklogError {
    BacklogError::Redpanda {
        operation,
        message: format!(
            "Kafka Redpanda listener {redpanda_bootstrap_servers} does not support inline request/reply; skipping request"
        ),
    }
}

fn redpanda_port(host_port: &str) -> Option<u16> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest
            .get(end + 1..)
            .and_then(|tail| tail.strip_prefix(':'))
            .and_then(|port| port.parse::<u16>().ok());
    }

    host_port
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

trait RedpandaStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> RedpandaStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct RedpandaEndpoint {
    address: String,
    host: String,
    tls_enabled: bool,
}

fn parse_redpanda_endpoint(redpanda_bootstrap_servers: &str) -> Result<RedpandaEndpoint, String> {
    let trimmed = redpanda_bootstrap_servers.trim();
    let (tls_enabled, without_scheme) = if let Some(value) = trimmed.strip_prefix("tls://") {
        (true, value)
    } else if let Some(value) = trimmed.strip_prefix("redpanda://") {
        (false, value)
    } else {
        (false, trimmed)
    };
    let authority = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| "missing Redpanda authority".to_string())?;
    if authority.is_empty() {
        return Err("missing Redpanda authority".to_string());
    }
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let has_port = if host_port.starts_with('[') {
        host_port.find(']').is_some_and(|end| {
            host_port
                .get(end + 1..)
                .is_some_and(|tail| tail.starts_with(':'))
        })
    } else {
        host_port.contains(':')
    };
    let address = if has_port {
        host_port.to_string()
    } else {
        format!("{host_port}:9092")
    };
    let host = if host_port.starts_with('[') {
        let end = host_port
            .find(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        host_port[1..end].to_string()
    } else {
        host_port
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(host_port)
            .to_string()
    };
    if host.is_empty() {
        return Err("missing Redpanda host".to_string());
    }
    Ok(RedpandaEndpoint {
        address,
        host,
        tls_enabled,
    })
}

fn build_tls_client_config(sync: &SyncConfig) -> Result<Option<Arc<rustls::ClientConfig>>, String> {
    if sync.redpanda_bootstrap_servers.as_deref().is_none() {
        return Ok(None);
    }

    let tls_required = sync
        .redpanda_bootstrap_servers
        .as_deref()
        .is_some_and(|url| url.trim().starts_with("tls://"))
        || sync
            .security_protocol
            .as_deref()
            .is_some_and(|protocol| protocol.to_ascii_uppercase().contains("SSL"));
    if !tls_required {
        return Ok(None);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    let ca_cert_path = sync.ssl_ca_location.as_deref().ok_or_else(|| {
        "SYNC_REDPANDA_SSL_CA_LOCATION is required when TLS is enabled".to_string()
    })?;
    let ca_pem = std::fs::read(ca_cert_path)
        .map_err(|error| format!("read Redpanda CA certificate {ca_cert_path}: {error}"))?;
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(ca_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse Redpanda CA certificate {ca_cert_path}: {error}"))?;
    let (added, _ignored) = roots.add_parsable_certificates(ca_certs);
    if added == 0 {
        return Err(format!(
            "no trust anchors loaded from Redpanda CA certificate {ca_cert_path}"
        ));
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_config = if let (Some(cert_path), Some(key_path)) = (
        sync.ssl_certificate_location.as_deref(),
        sync.ssl_key_location.as_deref(),
    ) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|error| format!("read Redpanda client certificate {cert_path}: {error}"))?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parse Redpanda client certificate {cert_path}: {error}"))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|error| format!("read Redpanda client key {key_path}: {error}"))?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
            .map_err(|error| format!("parse Redpanda client key {key_path}: {error}"))?
            .ok_or_else(|| format!("no private key found in {key_path}"))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|error| format!("build Redpanda TLS client auth config: {error}"))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Some(Arc::new(client_config)))
}

fn redpanda_tls_enabled(sync: &SyncConfig, endpoint: &RedpandaEndpoint) -> bool {
    endpoint.tls_enabled
        || sync
            .security_protocol
            .as_deref()
            .is_some_and(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
}

async fn connect_tls(
    connector: &TlsConnector,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let server_name = host.to_string();
    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|error| format!("invalid Redpanda TLS server name {server_name}: {error}"))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("establish Redpanda TLS session: {error}"))
}
