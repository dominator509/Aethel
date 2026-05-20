# NEED TO FIX: Comprehensive Remediation Roadmap

Based on the exhaustive analysis of all system reports across security, sanity, recovery, smoke testing, performance, usability, and 5G networking domains, the following is a detailed, instructional list of what must be done to make the Aethel network 100% production-ready.

## 0. Missing Reports
- **FUNCTIONAL_COVERAGE_REPORT.md**: This file was requested but **DOES NOT EXIST** in the repository. A full functional coverage pass must be executed and documented.

---

## 1. Networking & 5G URLLC Deficiencies
**The Problem:** The `5G_URLLC_LATENCY_REPORT.md` and `USABILITY_AND_DX_HEURISTIC_REPORT.md` indicate that the core node still relies on raw TCP sockets communicating via unstructured byte arrays (`[0; 1024]`). This fundamentally breaks 5G URLLC requirements, causes TCP Head-of-Line (HoL) blocking, and prevents seamless mobile tower handovers.
**The Fixes:**
- [ ] **Rip out TCP:** Completely deprecate `tokio::net::TcpListener` in `core_node/src/main.rs`.
- [ ] **Implement QUIC:** Fully integrate `quinn::Endpoint` across the `core_node` and `network` layers to enable multiplexed UDP, eliminating HoL blocking.
- [ ] **Connection Migration:** Implement IP-agnostic connection identifiers via the QUIC protocol to allow clients to switch IPs (tower handovers) without dropping the session.
- [ ] **Structured Serialization:** Replace raw byte parsing with `bincode` and `serde` over the wire.

---

## 2. Developer Experience (DX) & Usability Friction
n*Note: Implementation of heavy REST/gRPC APIs was rejected to preserve URLLC performance. See EXPLANATIONS_AND_REJECTIONS.md*
**The Problem:** The system is "fundamentally hostile to integration." Clients interacting with the raw socket receive silent closures (TCP FIN/RST) on timeouts instead of actionable error payloads. There is no CLI or GUI.
**The Fixes:**
- [ ] **Implement an RPC/API Layer:** Build a structured API (e.g., gRPC, GraphQL, or a RESTful wrapper) on top of the network layer.
- [ ] **Ergonomic Error Payloads:** Ensure that connection timeouts, validation failures, and cryptographic rejections return structured JSON or Protobuf error payloads detailing *exactly* why the connection was terminated.
- [ ] **CLI Implementation:** Integrate `clap` to build a Node Operator CLI. Hardcoded ports (`8080`) and limits must be moved to command-line arguments and configuration files.

---

## 3. Security & Access Control Hardening
n*Note: SPIFFE/SPIRE mTLS mesh was rejected to avoid IPC proxy latency. See EXPLANATIONS_AND_REJECTIONS.md*
**The Problem:** The `SECURITY_AUDIT_REPORT.md` notes that while the core protocol logic gracefully handles failures and drops malicious inputs via `ErrorKind::InvalidData`, the cluster lacks robust identity management. The report explicitly warns of high exploitability for unknown zero-days in experimental crypto libraries, and states: "The node relies on raw QUIC certs."
**The Fixes:**
- [ ] **mTLS SPIFFE/SPIRE Mesh:** Transition internal node RPC clustering from raw self-signed QUIC certificates to a full mTLS SPIFFE/SPIRE identity mesh for authenticated peer-to-peer routing.
- [ ] **Fuzzing Campaigns:** Expand `libfuzzer_sys` harnesses specifically targeting the `pqcrypto` and `aws-lc-rs` integration boundaries to preempt zero-days.

---

## 4. Legacy Scaffolding Artifacts
**The Problem:** Several reports (Sanity, Recovery, Performance) contain legacy artifacts indicating "FATAL FAILURE" or "IRREVOCABLE FAILURE" due to a missing `Cargo.toml`.
**The Fixes:**
- [ ] **Report Reconciliation:** While the codebase has been subsequently fixed (the workspace now compiles perfectly), the legacy markdown reports containing these false-positive "system missing" errors must be re-run and overwritten against the live, compiling codebase to reflect true runtime metrics rather than build scaffolding errors.
