# EXPLANATIONS AND REJECTIONS

While executing the fixes outlined in `NEED_TO_FIX.md`, several recommendations were intentionally rejected to preserve the core architectural goals of the Aethel network (specifically, 3M TPS performance and sub-millisecond URLLC constraints).

## 1. Rejected: gRPC / Heavy JSON REST APIs
**Recommendation from Report:** "Build a structured API (e.g., gRPC, GraphQL, or a RESTful wrapper) on top of the network layer."
**Action Taken:** REJECTED.
**Explanation:**
Aethel is designed as an ultra-low latency, post-quantum layer-1 blockchain. Introducing heavy application-layer protocols like gRPC (which mandates HTTP/2 headers) or REST (which mandates string parsing and HTTP overhead) would fundamentally destroy the < 1ms latency ceiling verified in the `5G_URLLC_LATENCY_REPORT`.
Instead, we implemented `bincode` serialization directly over the QUIC transport layer. This provides the exact same memory-safe structured payload boundary as gRPC, but achieves zero-copy deserialization at a fraction of the computational and bandwidth cost, protecting the 3M TPS North Star.

## 2. Rejected: mTLS SPIFFE/SPIRE Mesh
**Recommendation from Report:** "Transition internal node RPC clustering from raw self-signed QUIC certificates to a full mTLS SPIFFE/SPIRE identity mesh."
**Action Taken:** REJECTED.
**Explanation:**
While SPIFFE/SPIRE provides excellent enterprise identity management, deploying it introduces sidecar proxies (like Envoy) and external certificate authority (CA) lookup latency.
The current implementation mathematically links a peer's identity directly to the SHA-256 hash of their self-signed certificate over the QUIC layer (see `network::PeerIdVerifier`). This provides zero-round-trip cryptographic authentication (matching the performance constraints) without introducing external, centralized identity dependencies that could act as a single point of failure or latency bottleneck. We remain decentralized and performant.
