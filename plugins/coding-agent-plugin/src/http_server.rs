use std::io::Read;
use std::sync::Arc;

use crate::broker::Broker;
use crate::config::CodingAgentConfig;

/// Max HTTP request body size (1MB — Falco alerts are typically a few KB).
const MAX_BODY_SIZE: u64 = 1024 * 1024;

/// Falco JSON alert structure (subset of fields we need).
#[derive(serde::Deserialize)]
struct FalcoAlert {
    #[serde(default)]
    rule: String,
    #[serde(default)]
    output: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    output_fields: serde_json::Map<String, serde_json::Value>,
}

/// The verdict type determined from alert tags.
enum VerdictType {
    Deny,
    Ask,
    Seen,
    Unknown,
}

/// Start the HTTP alert receiver in a background thread.
/// Listens for Falco JSON alerts via http_output and resolves verdicts.
pub fn start(
    config: &CodingAgentConfig,
    broker: Arc<Broker>,
) -> std::thread::JoinHandle<()> {
    let deny_tags = config.deny_tags.clone();
    let ask_tags = config.ask_tags.clone();
    let seen_tags = config.seen_tags.clone();
    let bind_addr = format!("127.0.0.1:{}", config.http_port);

    std::thread::Builder::new()
        .name("cak-http-server".to_string())
        .spawn(move || run_server(&bind_addr, &deny_tags, &ask_tags, &seen_tags, &broker))
        .expect("failed to spawn HTTP server thread")
}

fn run_server(
    bind_addr: &str,
    deny_tags: &[String],
    ask_tags: &[String],
    seen_tags: &[String],
    broker: &Broker,
) {
    let server = match tiny_http::Server::http(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            log::error!("failed to bind HTTP server on {}: {}", bind_addr, e);
            return;
        }
    };

    // Log the actual bound address (important when http_port=0 for auto-assign).
    log::info!(
        "HTTP alert receiver listening on {}",
        server.server_addr().to_ip().map_or_else(
            || bind_addr.to_string(),
            |addr| addr.to_string(),
        )
    );

    for mut request in server.incoming_requests() {
        // Respond 200 immediately to avoid blocking Falco's output worker.
        // Parse and process the alert asynchronously (in this same thread,
        // since tiny_http is synchronous and we process sequentially).
        let mut body = String::new();
        if let Err(e) = request.as_reader().take(MAX_BODY_SIZE).read_to_string(&mut body) {
            log::warn!("failed to read HTTP request body: {}", e);
            let response = tiny_http::Response::empty(200);
            let _ = request.respond(response);
            continue;
        }

        // Respond immediately before processing.
        let response = tiny_http::Response::empty(200);
        let _ = request.respond(response);

        // Parse the Falco alert JSON.
        let alert: FalcoAlert = match serde_json::from_str(&body) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("malformed Falco alert JSON: {}", e);
                continue;
            }
        };

        // Extract the broker-assigned correlation ID from output_fields.
        // Falco serializes u64 fields as JSON numbers.
        let correlation_id = match alert
            .output_fields
            .get("correlation.id")
            .and_then(|v| v.as_u64())
        {
            Some(id) if id > 0 => id,
            _ => {
                log::debug!(
                    "alert missing correlation.id in output_fields (rule={})",
                    alert.rule
                );
                continue;
            }
        };

        // Determine verdict type from tags.
        let verdict_type = classify_tags(&alert.tags, deny_tags, ask_tags, seen_tags);

        // Build reason string from rule name and output.
        let reason = if alert.output.is_empty() {
            alert.rule.clone()
        } else {
            format!("{}: {}", alert.rule, alert.output)
        };

        // Apply verdict to the broker.
        match verdict_type {
            VerdictType::Deny => {
                log::debug!("deny alert for {} (rule={})", correlation_id, alert.rule);
                broker.apply_deny(correlation_id, reason);
            }
            VerdictType::Ask => {
                log::debug!("ask alert for {} (rule={})", correlation_id, alert.rule);
                broker.apply_ask(correlation_id, reason);
            }
            VerdictType::Seen => {
                log::debug!("seen alert for {}", correlation_id);
                broker.apply_seen(correlation_id);
            }
            VerdictType::Unknown => {
                log::debug!(
                    "alert with unrecognized tags for {} (rule={}, tags={:?})",
                    correlation_id,
                    alert.rule,
                    alert.tags
                );
            }
        }
    }
}

/// Classify an alert's tags into a verdict type.
/// Priority: deny > ask > seen > unknown.
fn classify_tags(
    tags: &[String],
    deny_tags: &[String],
    ask_tags: &[String],
    seen_tags: &[String],
) -> VerdictType {
    let mut result = VerdictType::Unknown;

    for tag in tags {
        if deny_tags.contains(tag) {
            return VerdictType::Deny; // Deny wins immediately.
        }
        if ask_tags.contains(tag) {
            result = VerdictType::Ask;
        }
        if seen_tags.contains(tag) && matches!(result, VerdictType::Unknown) {
            result = VerdictType::Seen;
        }
    }

    result
}
