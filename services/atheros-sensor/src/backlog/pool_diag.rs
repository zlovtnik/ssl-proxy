use tokio_postgres::{config::Host, Config as PostgresConfig};

pub(super) fn database_target(config: &PostgresConfig) -> String {
    let hosts = config.get_hosts();
    let ports = config.get_ports();
    let host = hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            let port = ports.get(index).copied().unwrap_or(5432);
            match host {
                Host::Tcp(host) => format!("{host}:{port}"),
                Host::Unix(path) => path.display().to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    let dbname = config.get_dbname().unwrap_or("<default>");
    let user = config.get_user().unwrap_or("<default>");
    format!("host={host}; dbname={dbname}; user={user}")
}
