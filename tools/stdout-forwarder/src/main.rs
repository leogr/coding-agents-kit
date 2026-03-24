//! Reads JSON lines from stdin and POSTs each to an HTTP endpoint.
//!
//! Used on Windows to bridge Falco's stdout_output to the plugin's HTTP server,
//! since Falco's http_output is not available in MINIMAL_BUILD on Windows.
//!
//! Usage: falco ... | stdout-forwarder http://127.0.0.1:2802

use std::io::{self, BufRead};
use std::net::TcpStream;

fn main() {
    let url = match std::env::args().nth(1) {
        Some(u) => u,
        None => {
            eprintln!("Usage: stdout-forwarder <http-url>");
            eprintln!("  e.g.: falco ... | stdout-forwarder http://127.0.0.1:2802");
            std::process::exit(1);
        }
    };

    // Parse host:port from URL
    let addr = url
        .strip_prefix("http://")
        .unwrap_or(&url)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:2802");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        // Minimal HTTP POST — no external dependencies, just raw TCP.
        if let Err(e) = post_line(addr, trimmed) {
            eprintln!("stdout-forwarder: POST failed: {e}");
        }
    }
}

fn post_line(addr: &str, body: &str) -> Result<(), String> {
    use std::io::Write;

    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();

    let request = format!(
        "POST / HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    // Read response (just drain it)
    let mut buf = [0u8; 256];
    let _ = std::io::Read::read(&mut stream, &mut buf);

    Ok(())
}
