use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use dashmap::DashMap;

use crate::verdict::Verdict;

/// Tracks pending requests from interceptors, waiting for verdict resolution.
pub struct Broker {
    /// Maps correlation ID → pending request.
    pending: DashMap<u64, PendingRequest>,
    /// Monotonic counter for generating correlation IDs.
    next_id: AtomicU64,
    /// When true, all verdicts resolve as allow (monitor mode).
    monitor_mode: AtomicBool,
}

/// A pending request from an interceptor, awaiting a verdict.
struct PendingRequest {
    /// The Unix socket connection back to the interceptor.
    stream: Mutex<UnixStream>,
    /// The wire protocol request ID (to include in the response).
    wire_id: String,
    /// The current best verdict (escalated as alerts arrive).
    current_verdict: Mutex<Option<Verdict>>,
}

impl Broker {
    pub fn new() -> Self {
        Broker {
            pending: DashMap::new(),
            next_id: AtomicU64::new(1),
            monitor_mode: AtomicBool::new(false),
        }
    }

    /// Generate a unique correlation ID for an event.
    pub fn next_correlation_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Set the operational mode. In monitor mode, all verdicts resolve as allow.
    pub fn set_monitor_mode(&self, enabled: bool) {
        self.monitor_mode.store(enabled, Ordering::Relaxed);
        log::info!(
            "broker mode: {}",
            if enabled { "monitor" } else { "enforcement" }
        );
    }

    /// Returns true if monitor mode is active.
    fn is_monitor(&self) -> bool {
        self.monitor_mode.load(Ordering::Relaxed)
    }

    /// Register a new pending request. `correlation_id` is the broker-assigned ID
    /// used for Falco alert correlation. `wire_id` is the interceptor's request ID
    /// used in the verdict response.
    pub fn register(&self, correlation_id: u64, wire_id: String, stream: UnixStream) {
        self.pending.insert(
            correlation_id,
            PendingRequest {
                stream: Mutex::new(stream),
                wire_id,
                current_verdict: Mutex::new(None),
            },
        );
    }

    /// Send a deny response directly on a stream (without registering in pending).
    /// Used when the event cannot be processed (e.g., queue full).
    pub fn send_deny(stream: UnixStream, correlation_id: &str, reason: &str) {
        let response = Verdict::Deny(reason.to_string()).to_response_json(correlation_id);
        let mut stream = stream;
        let _ = write!(stream, "{}\n", response);
        let _ = stream.shutdown(Shutdown::Both);
    }

    /// Apply a deny verdict. Deny wins immediately — resolve and respond.
    pub fn apply_deny(&self, correlation_id: u64, reason: String) {
        if self.is_monitor() {
            // In monitor mode, log the deny but don't resolve yet — wait for seen.
            log::info!("monitor: would deny {} ({})", correlation_id, reason);
            return;
        }
        self.resolve(correlation_id, Verdict::Deny(reason));
    }

    /// Apply an ask verdict. Escalate: only upgrade if not already deny.
    pub fn apply_ask(&self, correlation_id: u64, reason: String) {
        if self.is_monitor() {
            // In monitor mode, log the ask but don't resolve yet — wait for seen.
            log::info!("monitor: would ask {} ({})", correlation_id, reason);
            return;
        }
        if let Some(pending) = self.pending.get(&correlation_id) {
            let mut current = pending
                .current_verdict
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let new_verdict = Verdict::Ask(reason);
            *current = Some(match current.take() {
                Some(existing) => existing.escalate(new_verdict),
                None => new_verdict,
            });
        }
        // Don't resolve yet — wait for the seen signal.
    }

    /// Signal that rule evaluation is complete for this correlation ID.
    /// Resolve with the current best verdict (allow if no deny/ask arrived).
    /// In monitor mode, always resolves as allow.
    pub fn apply_seen(&self, correlation_id: u64) {
        if self.is_monitor() {
            // Monitor mode: always allow.
            self.resolve(correlation_id, Verdict::Allow);
            return;
        }
        // Atomically remove the entry. Only one caller wins the remove.
        if let Some((_, pending)) = self.pending.remove(&correlation_id) {
            let verdict = pending
                .current_verdict
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .unwrap_or(Verdict::Allow);
            let response = verdict.to_response_json(&pending.wire_id);
            let mut stream = pending.stream.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(stream, "{}\n", response);
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Resolve a pending request: send the verdict response to the interceptor
    /// and remove the request from the pending map. The response uses the wire_id
    /// (the interceptor's original request ID), not the broker's correlation ID.
    fn resolve(&self, correlation_id: u64, verdict: Verdict) {
        if let Some((_, pending)) = self.pending.remove(&correlation_id) {
            let response = verdict.to_response_json(&pending.wire_id);
            let mut stream = pending.stream.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(stream, "{}\n", response);
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Number of currently pending requests.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
