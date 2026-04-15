# Tests

## Interceptor Tests

```bash
make test-interceptor
```

Tests the interceptor against a Python mock broker. No Falco needed. Covers: verdict round-trips, fail-closed behavior, malformed input handling, timeout, large payloads.

## End-to-End Tests

```bash
make test-e2e
```

Requires Falco 0.43+ in PATH with the built plugin and interceptor. Tests the full pipeline: interceptor → plugin → Falco rule evaluation → HTTP alert → verdict resolution. Covers: deny rules, ask rules, allow (seen), multiple tool types, path resolution, verdict escalation, monitor mode.

## Run All Tests

```bash
make test
```

## Test Utilities

| File | Purpose |
|------|---------|
| `mock_broker.py` | Python mock broker for interceptor unit tests |
| `falco.yaml` | Empty Falco config for self-contained e2e tests |
| `test_interceptor.sh` | Interceptor test harness (19 tests) |
| `test_e2e.sh` | E2E test harness (40 tests) |
