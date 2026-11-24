//! Host workers register for P (CONNECT) or D (DNS-over-TLS), authenticate,
//! acknowledge assignments with A, then carry one unmodified stream.
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LIMIT: usize = 128;
const DNS_CLIENT_LIMIT: usize = 32;
const WAIT: Duration = Duration::from_secs(5);
const HANDSHAKE: Duration = Duration::from_secs(2);

fn debug(message: std::fmt::Arguments<'_>) {
    if env::var("MAC_BRIDGE_LOG_LEVEL").as_deref() == Ok("debug") {
        eprintln!("DEBUG mac-egress-bridge {message}");
    }
}

struct Permit(Arc<AtomicUsize>);

impl Permit {
    fn acquire(count: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < limit).then_some(value + 1)
            })
            .ok()
            .map(|_| Self(count.clone()))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Worker {
    stream: TcpStream,
    _permit: Permit,
}

fn authenticate(stream: &mut TcpStream, token: &[u8]) -> io::Result<Option<u8>> {
    stream.set_read_timeout(Some(HANDSHAKE))?;
    // A total deadline also bounds a peer trickling authentication bytes.
    let deadline = Instant::now() + HANDSHAKE;
    let mut supplied = Vec::new();
    while supplied.len() < 128 {
        stream.set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            let mut difference = supplied.len() ^ (token.len() + 1);
            for (index, expected) in token.iter().enumerate() {
                difference |= usize::from(supplied.get(index + 1).copied().unwrap_or(0) ^ expected);
            }
            stream.set_read_timeout(None)?;
            return Ok(match supplied.first() {
                Some(&kind @ (b'P' | b'D')) if difference == 0 => Some(kind),
                _ => None,
            });
        }
        supplied.push(byte[0]);
        if Instant::now() >= deadline {
            break;
        }
    }
    Ok(None)
}

fn copy_direction(mut reader: TcpStream, mut writer: TcpStream, protocol: &str, direction: &str) {
    match io::copy(&mut reader, &mut writer) {
        Ok(bytes) => {
            let _ = writer.shutdown(Shutdown::Write);
            debug(format_args!(
                "stream closed protocol={protocol} direction={direction} bytes={bytes}"
            ));
        }
        Err(error) => {
            let _ = reader.shutdown(Shutdown::Both);
            let _ = writer.shutdown(Shutdown::Both);
            debug(format_args!(
                "stream failed protocol={protocol} direction={direction} error={error}"
            ));
        }
    }
}

fn pair(client: TcpStream, worker: Worker, protocol: &'static str) -> io::Result<()> {
    worker.stream.set_read_timeout(None)?;
    worker.stream.set_write_timeout(None)?;
    let client_read = client.try_clone()?;
    let worker_write = worker.stream.try_clone()?;
    let worker_read = worker.stream.try_clone()?;
    let upload =
        thread::spawn(move || copy_direction(client_read, worker_write, protocol, "upload"));
    copy_direction(worker_read, client, protocol, "download");
    let _ = upload.join();
    Ok(())
}

fn serve_clients(listener: TcpListener, kind: u8, receiver: mpsc::Receiver<Worker>, limit: usize) {
    let workers = Arc::new(Mutex::new(receiver));
    let count = Arc::new(AtomicUsize::new(0));
    let protocol = if kind == b'D' { "dns-tls" } else { "connect" };
    for client in listener.incoming() {
        let Ok(client) = client else { continue };
        let Some(permit) = Permit::acquire(&count, limit) else {
            debug(format_args!(
                "client limit reached protocol={protocol} limit={limit}"
            ));
            continue;
        };
        let workers = workers.clone();
        thread::spawn(move || {
            let _permit = permit;
            let started = Instant::now();
            let deadline = started + WAIT;
            while Instant::now() < deadline {
                let receiver = workers.lock().unwrap();
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                let result = receiver.recv_timeout(remaining);
                drop(receiver);
                let Ok(mut worker) = result else { break };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let timeout = Some(remaining.min(HANDSHAKE));
                let mut acknowledgement = [0];
                let ready = worker
                    .stream
                    .set_read_timeout(timeout)
                    .and_then(|_| worker.stream.set_write_timeout(timeout))
                    .and_then(|_| worker.stream.write_all(&[kind]))
                    .and_then(|_| worker.stream.read_exact(&mut acknowledgement));
                if ready.is_ok() && acknowledgement == [b'A'] {
                    debug(format_args!(
                        "worker assigned protocol={protocol} wait_ms={}",
                        started.elapsed().as_millis()
                    ));
                    if let Err(error) = pair(client, worker, protocol) {
                        debug(format_args!(
                            "stream setup failed protocol={protocol} error={error}"
                        ));
                    }
                    return;
                }
                let reason = ready.err().map_or_else(
                    || "invalid acknowledgement".into(),
                    |error| error.to_string(),
                );
                debug(format_args!(
                    "worker assignment failed protocol={protocol} reason={reason}"
                ));
                // Drop stale workers and retry without consuming client bytes.
            }
            debug(format_args!(
                "no worker available protocol={protocol} wait_ms={}",
                started.elapsed().as_millis()
            ));
        });
    }
}

fn bind(variable: &str, default: &str) -> io::Result<TcpListener> {
    TcpListener::bind(env::var(variable).unwrap_or_else(|_| default.to_string()))
}

fn main() -> io::Result<()> {
    let token = fs::read(
        env::var("MAC_BRIDGE_TOKEN_FILE")
            .unwrap_or_else(|_| "/run/local-secrets/admin_api_key".into()),
    )?;
    let token = token.strip_suffix(b"\n").unwrap_or(&token).to_vec();
    if token.len() != 64 || !token.iter().all(u8::is_ascii_hexdigit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bridge token file",
        ));
    }
    let proxy = bind("MAC_BRIDGE_PROXY_ADDR", "127.0.0.1:18080")?;
    let dns = bind("MAC_BRIDGE_DNS_ADDR", "127.0.0.1:1853")?;
    let workers = bind("MAC_BRIDGE_WORKER_ADDR", "0.0.0.0:18081")?;
    println!(
        "mac-egress-bridge ready proxy={} dns={} worker={}",
        proxy.local_addr()?,
        dns.local_addr()?,
        workers.local_addr()?
    );
    io::stdout().flush()?;
    let (proxy_sender, proxy_receiver) = mpsc::sync_channel(LIMIT);
    let (dns_sender, dns_receiver) = mpsc::sync_channel(LIMIT);
    thread::spawn(move || serve_clients(proxy, b'P', proxy_receiver, LIMIT - DNS_CLIENT_LIMIT));
    thread::spawn(move || serve_clients(dns, b'D', dns_receiver, DNS_CLIENT_LIMIT));
    let count = Arc::new(AtomicUsize::new(0));
    let token = Arc::new(token);
    for stream in workers.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Some(permit) = Permit::acquire(&count, LIMIT) else {
            debug(format_args!("worker limit reached limit={LIMIT}"));
            continue;
        };
        let token = token.clone();
        let proxy_sender = proxy_sender.clone();
        let dns_sender = dns_sender.clone();
        thread::spawn(move || match authenticate(&mut stream, &token) {
            Ok(Some(kind)) => {
                let sender = if kind == b'D' {
                    dns_sender
                } else {
                    proxy_sender
                };
                if sender
                    .try_send(Worker {
                        stream,
                        _permit: permit,
                    })
                    .is_err()
                {
                    debug(format_args!("worker queue unavailable"));
                }
            }
            Ok(None) => debug(format_args!("worker registration rejected")),
            Err(error) => debug(format_args!(
                "worker authentication incomplete error={error}"
            )),
        });
    }
    Ok(())
}
