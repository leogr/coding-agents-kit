use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

use crossbeam_channel::Sender;

use crate::broker::{Broker, BrokerStream};
use crate::event::{EventData, InterceptorRequest};

/// Max request size from an interceptor (64KB + envelope overhead).
const MAX_REQUEST_SIZE: u64 = 128 * 1024;

/// Read timeout for interceptor connections (prevents slowloris).
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Start the broker socket server in a background thread.
///
/// On Unix, listens on a Unix domain socket at `socket_path`.
/// On Windows, `socket_path` is a TCP address (e.g. `127.0.0.1:2803`).
pub fn start(
    socket_path: String,
    event_tx: Sender<EventData>,
    broker: Arc<Broker>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("cak-socket-server".to_string())
        .spawn(move || run_server(&socket_path, &event_tx, &broker))
        .expect("failed to spawn socket server thread")
}

#[cfg(unix)]
fn run_server(socket_path: &str, event_tx: &Sender<EventData>, broker: &Broker) {
    // Remove stale socket file if it exists.
    let _ = std::fs::remove_file(socket_path);

    // Ensure parent directory exists.
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            log::error!("failed to bind Unix socket at {}: {}", socket_path, e);
            return;
        }
    };

    log::info!("broker listening on {}", socket_path);

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("failed to accept connection: {}", e);
                continue;
            }
        };

        let _ = stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT));

        if let Err(e) = handle_connection(stream, event_tx, broker) {
            log::warn!("connection error: {}", e);
        }
    }
}

#[cfg(windows)]
fn run_server(listen_addr: &str, event_tx: &Sender<EventData>, broker: &Broker) {
    let listener = match std::net::TcpListener::bind(listen_addr) {
        Ok(l) => l,
        Err(e) => {
            log::error!("failed to bind TCP listener at {}: {}", listen_addr, e);
            return;
        }
    };

    log::info!("broker listening on {}", listen_addr);

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("failed to accept connection: {}", e);
                continue;
            }
        };

        let _ = stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT));

        if let Err(e) = handle_connection(stream, event_tx, broker) {
            log::warn!("connection error: {}", e);
        }
    }
}

fn handle_connection(
    stream: BrokerStream,
    event_tx: &Sender<EventData>,
    broker: &Broker,
) -> Result<(), String> {
    // Read one newline-terminated JSON request.
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_REQUEST_SIZE))
        .read_line(&mut line)
        .map_err(|e| format!("read error: {e}"))?;

    if line.is_empty() {
        return Err("empty request".into());
    }

    // Parse wire protocol request.
    let request: InterceptorRequest =
        serde_json::from_str(&line).map_err(|e| format!("malformed request: {e}"))?;

    // Validate: agent name must not contain newlines (used in payload encoding).
    if request.agent_name.contains('\n') {
        return Err("agent name contains newline".into());
    }

    let wire_id = request.id.clone();
    let agent_name = request.agent_name.clone();

    // Broker assigns a unique correlation ID (monotonic u64 counter, always > 0).
    let correlation_id = broker.next_correlation_id();

    // Serialize the event field back to bytes for the Falco event payload.
    let raw_event = serde_json::to_vec(&request.event)
        .map_err(|e| format!("failed to serialize event: {e}"))?;

    let event_data = EventData {
        correlation_id,
        agent_name,
        raw_event,
    };

    // Register pending request BEFORE enqueuing the event. This ensures the broker
    // entry exists before Falco can process the event and send back an alert.
    // If enqueue fails, we remove the broker entry and deny.
    broker.register(correlation_id, wire_id, stream);

    if event_tx.try_send(event_data).is_err() {
        log::warn!("event queue full, denying event {}", correlation_id);
        broker.apply_deny(correlation_id, "event queue full".to_string());
        return Ok(());
    }

    Ok(())
}
