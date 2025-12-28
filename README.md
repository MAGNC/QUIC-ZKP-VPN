# QUIC-ZKP-VPN 🛡️⚛️

**A Post-Quantum VPN powered by QUIC and Cloudflare CIRCL.**

QUIC-ZKP-VPN is a high-performance, quantum-resistant VPN service written in Go. It accepts the reality of "store now, decrypt later" threats and mitigates them using state-of-the-art cryptographic primitives (ML-KEM, ML-DSA) and Zero-Knowledge Proofs for identity privacy.

## Features

-   **Transport**: BUILT on `quic-go` for multiplexed, low-latency streams (UDP).
-   **Post-Quantum Key Exchange**: **ML-KEM-768** (Kyber connectivity) for the handshake.
-   **Post-Quantum Signatures**: **ML-DSA-65** (Dilithium) for identity verification.
-   **Dual Authentication Modes**:
    -   **Mode A (Standard PQ)**: Mutual TLS (mTLS) with ML-DSA certificates.
    -   **Mode B (Anon-ZKP)**: 1-way TLS (Server Auth) + Schnorr Zero-Knowledge Proofs (Ristretto255) for client authentication inside the encrypted tunnel, preserving client anonymity from header inspection.

## Architecture

The project is structured into modular components:

-   `cmd/server`: The VPN server entrypoint.
-   `cmd/client`: The VPN client entrypoint.
-   `pkg/crypto`: Wrappers ensuring Cloudflare CIRCL keys satisfy Go's standard `crypto.Signer` interfaces.
-   `pkg/auth`: Implementation of Schnorr Non-Interactive ZKP protocol.

## Getting Started

### Prerequisites

-   Go 1.22+
-   (Optional) Make

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-org/QUIC-ZKP-VPN.git
cd QUIC-ZKP-VPN
go mod tidy
```

### Building

```bash
go build -o server ./cmd/server
go build -o client ./cmd/client
```

## Usage

The VPN uses **Flags** to select the Authentication/Quantum Mode (A or B) and **Configuration Files** to define Network Topology (IPs, Routing).

### 1. Server Usage

**Option 1: Quick Start (No TUN/Networking)**
Runs the server process without creating a virtual network interface.
```bash
# Mode A (mTLS)
./server -mode A -addr localhost:4242

# Mode B (Anon-ZKP)
./server -mode B -addr localhost:4242
```

**Option 2: Full VPN (With Config File)**
Required to create the TUN interface and enable packet forwarding.

1.  Create `server.conf`:
    ```text
    ifconfig 10.8.0.1 255.255.255.0
    ```
2.  Run with **sudo** (for TUN creation) and flags:
    ```bash
    # Mode A
    sudo ./server -mode A --config server.conf

    # Mode B
    sudo ./server -mode B --config server.conf
    ```

### 2. Client Usage

**Option 1: Quick Start (No TUN/Networking)**
Connects to server to verify handshake only.
```bash
# Mode A
./client -mode A -server localhost:4242

# Mode B
./client -mode B -server localhost:4242
```

**Option 2: Full VPN (With Config File)**
Required to create the TUN interface and assign a Virtual IP.

1.  Create `client.conf`:
    ```text
    remote localhost 4242
    ifconfig 10.8.0.5 255.255.255.0
    ```
    *(Note: `remote` line in config sets the server address, so you can omit `-server` flag)*

2.  Run with **sudo** and **Mode Flag**:
    ```bash
    # Mode A
    sudo ./client -mode A --config client.conf

    # Mode B
    sudo ./client -mode B --config client.conf
    ```

## Verification

If successful, you should see the handshake complete and the secure data stream established:

```
Server: ZKP Auth Success for ...
Client: ZKP Authentication Successful!
Client: Sent IP Registration: IP:10.8.0.5
```

## Security Note

Please do not use it for production environments, it is only for research purposes.
---
