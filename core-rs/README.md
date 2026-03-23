# core-rs — Rust Production Runtime

This directory will contain the Rust production runtime for the AEGIS governance enforcement engine.

## Status

**Not yet started.** The Python reference implementation in `core-py/` is being developed first to establish correctness and stabilize the governance protocol interfaces.

## Plan

1. Stabilize the Python reference implementation and AGP-1 protocol interfaces
2. Define comprehensive integration test suites that both implementations must pass
3. Port the governance pipeline to Rust, module by module:
   - `gateway` — AGP-1 message processing
   - `capability` — Capability registry
   - `policy` — Policy evaluation engine
   - `risk` — Risk scoring engine
   - `audit` — Audit logging
4. Validate that the Rust implementation passes the same integration tests as Python
5. Benchmark and optimize for low-latency, high-throughput policy evaluation

## Why Rust?

- **Performance** — Sub-millisecond policy evaluation for real-time governance
- **Memory safety** — Critical for a security-sensitive enforcement engine
- **Concurrency** — Efficient handling of high-volume ACTION_PROPOSE streams
- **FFI** — Can be consumed as a native library by aegis-platform (if needed)
