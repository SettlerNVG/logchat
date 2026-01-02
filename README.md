# LogChat

A secure, ephemeral terminal messenger with end-to-end encryption and peer-to-peer communication.

```
┌─────────────────────────────────────────────────────────────┐
│  "Messages that exist only in the moment"                   │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Quick Install (macOS/Linux)

```bash
curl -sSL https://raw.githubusercontent.com/SettlerNVG/logchat/main/install.sh | bash
```

After installation, just run:
```bash
logchat
```

### Manual Install

Download the latest release for your platform from [Releases](https://github.com/SettlerNVG/logchat/releases).

### Build from Source

```bash
git clone https://github.com/SettlerNVG/logchat
cd logchat
make build
./bin/logchat
```

## Features

- **End-to-End Encryption** — Curve25519 key exchange + AES-256-GCM
- **No Message Storage** — Messages exist only in RAM during chat
- **Peer-to-Peer** — Direct connection between users, server only coordinates
- **Dynamic Host Selection** — Automatic role assignment based on network capability
- **Terminal UI** — Clean TUI interface using Bubbletea

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CENTRAL SERVER                          │
│         (Auth, Users, Session Coordination)                 │
│                  ❌ NO MESSAGE STORAGE                       │
└─────────────────────────────────────────────────────────────┘
                          │
                    Coordination
                          │
     ┌────────────────────┴────────────────────┐
     │                                         │
┌────▼─────┐                             ┌─────▼────┐
│ Client A │◄═══════ P2P Stream ════════►│ Client B │
│  [HOST]  │      (E2EE Messages)        │ [CLIENT] │
└──────────┘                             └──────────┘
```

## Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- buf (for proto generation)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/logchat
cd logchat

# Install development tools
make setup

# Generate proto files
make proto

# Start infrastructure
make docker-up

# Build
make build
```

### Running

```bash
# Terminal 1: Start server (if not using Docker)
make run-server

# Terminal 2: Start client
./bin/logchat
```

## Project Structure

```
logmessager/
├── client/                 # Terminal client
│   ├── cmd/               # Entry point
│   ├── internal/
│   │   ├── config/        # Configuration
│   │   ├── crypto/        # E2EE implementation
│   │   ├── grpc/          # Server communication
│   │   ├── p2p/           # P2P host/client
│   │   └── tui/           # Terminal UI
│   └── go.mod
├── server/                 # Central server
│   ├── cmd/               # Entry point
│   ├── internal/
│   │   ├── auth/          # JWT, password hashing
│   │   ├── config/        # Configuration
│   │   ├── grpc/          # gRPC handlers
│   │   ├── repository/    # Database layer
│   │   └── service/       # Business logic
│   ├── migrations/        # SQL migrations
│   └── go.mod
├── proto/                  # Protocol Buffers
├── docker/                 # Docker configuration
└── docs/                   # Documentation
```

## Security Model

### Encryption Layers

1. **Transport**: TLS for all connections
2. **Identity**: Curve25519 key pairs per user
3. **Session**: Ephemeral Diffie-Hellman key exchange
4. **Messages**: AES-256-GCM encryption

### What the Server Knows

- ✅ Usernames and password hashes
- ✅ Public keys
- ✅ Online status
- ✅ Session metadata (who chatted with whom, when)
- ❌ Message content
- ❌ Session encryption keys

### What Gets Destroyed

- Session keys — destroyed when chat ends
- Messages — never written to disk
- Ephemeral keys — destroyed after key exchange

## Configuration

### Server (.env)

```env
SERVER_HOST=0.0.0.0
SERVER_GRPC_PORT=50051
DATABASE_URL=postgres://user:pass@localhost:5432/logmessager
JWT_SECRET=your-secret-key
```

### Client (~/.logchat/.env)

```env
CENTRAL_SERVER_ADDRESS=localhost:50051
P2P_PORT_RANGE_START=50000
P2P_PORT_RANGE_END=50999
```

## Development

```bash
# Run tests
make test

# Lint code
make lint

# Database migrations
make migrate-up
make migrate-down

# View logs
make docker-logs
```

## Protocol

### Chat Flow

1. **Request**: User A requests chat with User B
2. **Coordinate**: Server determines who will be host
3. **Accept**: User B accepts the request
4. **Connect**: Host starts P2P server, client connects
5. **Handshake**: Ephemeral key exchange
6. **Chat**: Encrypted bidirectional stream
7. **End**: Keys destroyed, session metadata logged

### Host Selection Logic

```
if A.can_accept_inbound:
    A = HOST
elif B.can_accept_inbound:
    B = HOST
else:
    ERROR: "No connection path available"
```

## Roadmap

- [x] Core architecture
- [x] Proto definitions
- [x] Proto code generation
- [x] Server: Auth & Users
- [x] Server: Session coordination
- [x] Client: Crypto (E2EE)
- [x] Client: P2P host/client
- [x] Client: TUI framework
- [x] Docker setup
- [x] CI/CD workflows
- [ ] TLS/mTLS
- [ ] NAT traversal (TURN)
- [ ] File transfer
- [ ] Multi-platform builds

## License

MIT

## Contributing

Contributions welcome! Please read the contributing guidelines first.
