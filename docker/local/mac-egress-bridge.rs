//! Local-only reverse TCP bridge. Host workers authenticate, await P (CONNECT)
//! or D (DNS-over-TLS), acknowledge with A, then carry one unmodified stream.
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LIMIT: usize = 128;
const WAIT: Duration = Duration::from_secs(5);
const HANDSHAKE: Duration = Duration::from_secs(2);

struct Permit(Arc<AtomicUsize>);

impl Permit {
    fn acquire(count: &Arc<AtomicUsize>) -> Option<Self> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < LIMIT).then_some(value + 1)
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

fn authenticate(stream: &mut TcpStream, token: &[u8]) -> io::Result<bool> {
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
            let mut difference = supplied.len() ^ token.len();
            for (index, expected) in token.iter().enumerate() {
                difference |= usize::from(supplied.get(index).copied().unwrap_or(0) ^ expected);
            }
            stream.set_read_timeout(None)?;
            return Ok(difference == 0);
        }
        supplied.push(byte[0]);
        if Instant::now() >= deadline {
            break;
        }
    }
    Ok(false)
}

fn copy_direction(mut reader: TcpStream, mut writer: TcpStream) {
    if io::copy(&mut reader, &mut writer).is_err() {
        let _ = reader.shutdown(Shutdown::Both);
        let _ = writer.shutdown(Shutdown::Both);
    } else {
        let _ = writer.shutdown(Shutdown::Write);
    }
}

fn pair(client: TcpStream, worker: Worker) -> io::Result<()> {
    worker.stream.set_read_timeout(None)?;
    worker.stream.set_write_timeout(None)?;
    let client_read = client.try_clone()?;
    let worker_write = worker.stream.try_clone()?;
    let worker_read = worker.stream.try_clone()?;
    let upload = thread::spawn(move || copy_direction(client_read, worker_write));
    copy_direction(worker_read, client);
    let _ = upload.join();
    Ok(())
}

fn serve_clients(
    listener: TcpListener,
    kind: u8,
    workers: Arc<Mutex<mpsc::Receiver<Worker>>>,
    count: Arc<AtomicUsize>,
) {
    for client in listener.incoming() {
        let Ok(client) = client else { continue };
        let Some(permit) = Permit::acquire(&count) else {
            continue;
        };
        let workers = workers.clone();
        thread::spawn(move || {
            let _permit = permit;
            let deadline = Instant::now() + WAIT;
            while Instant::now() < deadline {
                let receiver = workers.lock().unwrap();
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return;
                };
                let result = receiver.recv_timeout(remaining);
                drop(receiver);
                let Ok(mut worker) = result else { return };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
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
                    let _ = pair(client, worker);
                    return;
                }
                // Drop stale workers and retry without consuming client bytes.
            }
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
    let (sender, receiver) = mpsc::sync_channel(LIMIT);
    let receiver = Arc::new(Mutex::new(receiver));
    let proxy_receiver = receiver.clone();
    let client_count = Arc::new(AtomicUsize::new(0));
    let proxy_count = client_count.clone();
    thread::spawn(move || serve_clients(proxy, b'P', proxy_receiver, proxy_count));
    thread::spawn(move || serve_clients(dns, b'D', receiver, client_count));
    let count = Arc::new(AtomicUsize::new(0));
    let token = Arc::new(token);
    for stream in workers.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Some(permit) = Permit::acquire(&count) else {
            continue;
        };
        let token = token.clone();
        let sender = sender.clone();
        thread::spawn(move || {
            if authenticate(&mut stream, &token).unwrap_or(false) {
                let _ = sender.try_send(Worker {
                    stream,
                    _permit: permit,
                });
            }
        });
    }
    Ok(())
}
