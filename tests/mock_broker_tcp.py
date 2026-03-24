#!/usr/bin/env python3
"""
TCP mock broker for testing the interceptor on Windows.

Usage:
    mock_broker_tcp.py <port> [mode]

Modes:
    allow           - respond with allow (default)
    deny            - respond with deny + reason
    ask             - respond with ask + reason
    slow:<seconds>  - wait N seconds before responding (for timeout tests)
    close           - accept connection then close immediately (no response)
    bad_json        - respond with invalid JSON
    wrong_id        - respond with mismatched ID
"""

import json
import socket
import sys
import time


def main():
    if len(sys.argv) < 2:
        print("Usage: mock_broker_tcp.py <port> [mode]", file=sys.stderr)
        sys.exit(1)

    port = int(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "allow"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)

    # Signal readiness with the actual bound port.
    actual_port = server.getsockname()[1]
    print(f"READY:{actual_port}", flush=True)

    conn, _ = server.accept()
    try:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        if mode == "close":
            conn.close()
            return

        # Parse request to get the ID.
        try:
            req = json.loads(data.decode("utf-8").strip())
            req_id = req.get("id", "unknown")
        except (json.JSONDecodeError, UnicodeDecodeError):
            req_id = "unknown"

        print(f"REQUEST:{data.decode('utf-8').strip()}", flush=True)

        if mode.startswith("slow:"):
            delay = float(mode.split(":")[1])
            time.sleep(delay)
            resp = {"id": req_id, "decision": "allow", "reason": ""}
        elif mode == "deny":
            resp = {"id": req_id, "decision": "deny", "reason": "blocked by test rule"}
        elif mode == "ask":
            resp = {"id": req_id, "decision": "ask", "reason": "requires confirmation"}
        elif mode == "bad_json":
            conn.sendall(b"this is not json\n")
            return
        elif mode == "wrong_id":
            resp = {"id": "wrong-id-xxx", "decision": "allow", "reason": ""}
        else:
            resp = {"id": req_id, "decision": "allow", "reason": ""}

        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
    finally:
        conn.close()
        server.close()


if __name__ == "__main__":
    main()
