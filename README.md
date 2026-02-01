# LogChat

Secure P2P terminal messenger with end-to-end encryption.

Messages exist only in RAM during chat session. Nothing is stored on servers or disk.

## Features

- End-to-End Encryption (Curve25519 + AES-256-GCM)
- Peer-to-Peer direct connections via STUN
- No message storage (RAM only, destroyed after chat)
- Terminal UI with server selection
- TLS 1.3 for server communication
- Ed25519 signature verification
- Automatic reconnection
- Rate limiting protection
- NAT traversal

## Installation

### Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/SettlerNVG/logchat/main/install.sh | bash
```

### Update

```bash
curl -sSL https://raw.githubusercontent.com/SettlerNVG/logchat/main/install.sh | bash
```

Same command updates to latest version.

### Manual

Download from [Releases](https://github.com/SettlerNVG/logchat/releases):

```bash
wget https://github.com/SettlerNVG/logchat/releases/latest/download/logchat-linux-amd64
chmod +x logchat-linux-amd64
sudo mv logchat-linux-amd64 /usr/local/bin/logchat
```

## Quick Start

1. Launch: `logchat`
2. Select server (Localhost for testing)
3. Register: `register alice password123`
4. Login: `login alice password123`
5. Press Tab to see contacts, Enter to chat

### Connect to Server

Interactive (recommended):
```bash
logchat
# Select "Custom Server" and enter address
```

Command line:
```bash
logchat -server chat.example.com:50051
```

Environment variable:
```bash
export CENTRAL_SERVER_ADDRESS=chat.example.com:50051
logchat
```

Config file:
```bash
echo "CENTRAL_SERVER_ADDRESS=chat.example.com:50051" > ~/.logchat/.env
logchat
```

## Architecture

```
┌─────────────────────────────────────────┐
│         CENTRAL SERVER (gRPC)           │
│  - User authentication (JWT)            │
│  - Contact management                   │
│  - P2P coordination (STUN)              │
│  - Rate limiting                        │
│  - NO MESSAGE STORAGE                   │
└─────────────────────────────────────────┘
                    │
              Coordination
                    │
     ┌──────────────┴──────────────┐
     │                             │
┌────▼────┐                   ┌────▼────┐
│ Alice   │◄══════ P2P ══════►│  Bob    │
│ [HOST]  │   E2EE Messages   │[CLIENT] │
└─────────┘                   └─────────┘
```

### How It Works

1. Users authenticate via central server
2. STUN discovers public IP addresses
3. Server coordinates P2P connection
4. Messages flow directly between users
5. E2EE with ephemeral session keys
6. Keys destroyed after chat ends

## Security

### Encryption
- TLS 1.3 for client-server
- Ed25519 signatures for P2P auth
- Curve25519 ECDH for key exchange
- AES-256-GCM for messages

### Privacy
- Messages never touch server
- No message history
- Ephemeral keys (forward secrecy)
- Keys destroyed after session

### Protection
- Eavesdropping (TLS + E2EE)
- Man-in-the-Middle (TLS + signatures)
- Replay attacks (session tokens)
- Brute force (rate limiting)
- DoS attacks (rate limiting)

## Development

### Prerequisites
- Go 1.22+
- Docker & Docker Compose
- PostgreSQL (via Docker)

### Local Setup

```bash
git clone https://github.com/SettlerNVG/logchat.git
cd logchat

# Start server
make dev

# Build client
cd client
go build -o ../bin/logchat ./cmd
../bin/logchat
```

### Project Structure

```
logchat/
├── client/          # TUI client
├── server/          # gRPC server
├── proto/           # Protocol Buffers
├── docker/          # Docker configs
└── scripts/         # Build scripts
```


## Troubleshooting

### Connection timeout
Check server is running and address is correct.

### Username taken
Choose different username.

### P2P connection failed
One user needs port forwarding or public IP.

### Logs
```bash
# Client
tail -f /tmp/logchat.log

# Server
docker-compose -f docker/docker-compose.yml logs -f server
```


## License

MIT License - see [LICENSE](LICENSE).


- [Releases](https://github.com/SettlerNVG/logchat/releases)
