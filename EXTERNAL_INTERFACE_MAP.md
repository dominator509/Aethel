# EXTERNAL_INTERFACE_MAP

## Interface Discovery
*   **Protocol:** Custom P2P Protocol over QUIC (UDP).
*   **Port Config:** Dynamically bound (e.g., `127.0.0.1:0` for testing).
*   **Authentication:** mTLS. Both client and server must provide `rcgen`-generated X.509 certificates.
*   **Authorization:** The SHA256 hash of the presented X.509 certificate must exactly match the `PeerId` expected by the connection string.

## Endpoint Mappings

### 1. `Incoming Transaction Stream`
*   **Description:** An active listener waiting for inbound unidirectional streams over an established QUIC connection.
*   **Payload Schema:** Opaque byte array (`Vec<u8>`).
*   **Expected Serialization:** Internally handled (simulated `crypto::transaction::Transaction`).
*   **Constraints:**
    *   Maximum concurrent streams per peer: 1024.
    *   Maximum global concurrent streams: 10,000 (Semaphore bound).
    *   Maximum payload length: 1,048,576 bytes (1 MB).
    *   Timeout: 5 seconds per read operation.

### 2. `Outgoing Broadcast Hook`
*   **Description:** Initiates connections to remote peers to flush serialized byte payloads.
*   **Payload Schema:** Opaque byte array (`Vec<u8>`).
*   **Constraints:**
    *   3-second timeout for establishing connection and completing the write.
