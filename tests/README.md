# Tests

## Interceptor Tests

```bash
bash tests/test_interceptor.sh
```

Tests the interceptor against a Python mock broker. No Falco needed. Covers: verdict round-trips, fail-closed behavior, malformed input handling, timeout, large payloads.

## End-to-End Tests

```bash
bash tests/test_e2e.sh
```

Requires Falco 0.43+ with the built plugin and interceptor. Tests the full pipeline: interceptor → plugin → Falco rule evaluation → HTTP alert → verdict resolution. Covers: deny rules, ask rules, allow (seen), multiple tool types.

## Test Utilities

| File | Purpose |
|------|---------|
| `mock_broker.py` | Python mock broker for interceptor unit tests |
| `test_interceptor.sh` | Interceptor test harness (19 tests) |
| `test_e2e.sh` | E2E test harness (13 tests) |
