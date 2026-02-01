# LogChat

Secure P2P terminal messenger with end-to-end encryption.

Messages exist only in RAM during chat session — nothing is stored on servers or disk.

## ✨ Features

- **🔒 End-to-End Encryption** — Curve25519 + AES-256-GCM
- **🔗 Peer-to-Peer** — Direct connection between users via STUN
- **💾 No Message Storage** — Messages only in RAM, destroyed when chat ends
- **🖥️ Terminal UI** — Clean TUI interface with server selection
- **🔐 Security Features:**
  - TLS 1.3 for server communication
  - Ed25519 signature verification
  - Automatic reconnection with exponential backoff
  - Rate limiting protection
  - NAT traversal with STUN

## 📦 Installation

### Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/SettlerNVG/logchat/main/install.sh | bash
```

### Update to Latest Version

```bash
curl -sSL https://raw.githubusercontent.com/SettlerNVG/logchat/main/install.sh | bash
```

The installer automatically updates to the latest version.

### Manual Installation

Download from [Releases](https://github.com/SettlerNVG/logchat/releases) and place in your PATH:

```bash
# Download for your platform
wget https://github.com/SettlerNVG/logchat/releases/latest/download/logchat-linux-amd64

# Make executable
chmod +x logchat-linux-amd64

# Move to PATH
sudo mv logchat-linux-amd64 /usr/local/bin/logchat
```

## 🚀 Quick Start

### First Time Usage

1. **Launch the app:**
   ```bash
   logchat
   ```

2. **Select server:**
   - Choose `Localhost` for local development
   - Choose `Custom Server` to enter your server address

3. **Register:**
   ```
   > register alice password123
   ```

4. **Login:**
   ```
   > login alice password123
   ```

5. **Start chatting:**
   - Press `Tab` to see contacts
   - Select a user and press `Enter`
   - Wait for them to accept

### Connecting to Different Servers

**Option 1: Interactive (Recommended)**
```bash
logchat
# Select "Custom Server" and enter address
```

**Option 2: Command line flag**
```bash
logchat -server chat.example.com:50051
```

**Option 3: Environment variable**
```bash
export CENTRAL_SERVER_ADDRESS=chat.example.com:50051
logchat
```

**Option 4: Config file**
```bash
mkdir -p ~/.logchat
echo "CENTRAL_SERVER_ADDRESS=chat.example.com:50051" > ~/.logchat/.env
logchat
```

### TLS Configuration

- **Localhost:** TLS automatically disabled
- **ngrok:** TLS automatically disabled (ngrok provides encryption)
- **Production servers:** TLS automatically enabled with system CA pool
- **Custom certificates:** Set `TLS_CA_FILE` in `~/.logchat/.env`

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         CENTRAL SERVER (gRPC)           │
│  • User authentication (JWT)            │
│  • Contact management                   │
│  • P2P coordination (STUN)              │
│  • Rate limiting                        │
│  ❌ NO MESSAGE STORAGE                  │
└─────────────────────────────────────────┘
                    │
              Coordination
                    │
     ┌──────────────┴──────────────┐
     │                             │
┌────▼────┐                   ┌────▼────┐
│ Alice   │◄══════ P2P ══════►│  Bob    │
│ [HOST]  │   E2EE Messages   │[CLIENT] │
│         │   Direct Connect  │         │
└─────────┘                   └─────────┘
```

### How It Works

1. **Authentication:** Users register/login via central server
2. **STUN Discovery:** Client discovers public IP via free STUN servers
3. **P2P Setup:** Server coordinates who will be host based on NAT types
4. **Direct Connection:** Messages flow directly between users (P2P)
5. **E2EE:** All messages encrypted with ephemeral session keys
6. **Session End:** Keys destroyed, messages gone from RAM

## 🔐 Security

### Transport Layer
- **TLS 1.3** for client-server communication
- **Ed25519** signatures for P2P authentication
- **Curve25519** ECDH for key exchange
- **AES-256-GCM** for message encryption

### Privacy
- Messages never touch the server
- No message history or logs
- Ephemeral keys (forward secrecy)
- Session keys destroyed after chat

### Protection Against
- ✅ Eavesdropping (TLS + E2EE)
- ✅ Man-in-the-Middle (TLS + signatures)
- ✅ Replay attacks (session tokens)
- ✅ Brute force (rate limiting)
- ✅ DoS attacks (rate limiting)

## 🛠️ Development

### Prerequisites
- Go 1.22+
- Docker & Docker Compose
- PostgreSQL (via Docker)

### Local Development

```bash
# Clone repository
git clone https://github.com/SettlerNVG/logchat.git
cd logchat

# Start server (PostgreSQL + gRPC server)
make dev

# Build and run client
cd client
go build -o ../bin/logchat ./cmd
../bin/logchat
```

### Project Structure

```
logchat/
├── client/          # TUI client application
│   ├── cmd/         # Entry point
│   └── internal/    # Client logic (TUI, P2P, crypto)
├── server/          # gRPC server
│   ├── cmd/         # Entry point
│   ├── internal/    # Server logic (auth, DB, sessions)
│   └── migrations/  # Database migrations
├── proto/           # Protocol Buffers definitions
├── docker/          # Docker configurations
└── scripts/         # Build and deployment scripts
```

## 📚 Documentation

- [Security Features](SECURITY_FEATURES.md) - Complete security overview
- [NAT Traversal](docs/NAT_TRAVERSAL.md) - How STUN works
- [TLS Setup](docs/TLS_SETUP.md) - TLS configuration guide
- [Signature Verification](docs/SIGNATURE_VERIFICATION.md) - P2P authentication
- [Reconnection](docs/RECONNECTION.md) - Auto-reconnect logic

## 🐛 Troubleshooting

### Cannot connect to server
```
✗ Connection timeout. Please check your internet connection.
```
**Solution:** Check if server is running and address is correct.

### Username already taken
```
✗ Username already taken. Please choose another.
```
**Solution:** Choose a different username.

### Cannot establish P2P connection
```
✗ Cannot establish P2P connection. Both users may be behind strict NAT.
```
**Solution:** One user should have port forwarding enabled, or use a server with public IP.

### Check logs
```bash
# Client logs
tail -f /tmp/logchat.log

# Server logs (Docker)
docker-compose -f docker/docker-compose.yml logs -f server
```

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [GitHub Repository](https://github.com/SettlerNVG/logchat)
- [Issue Tracker](https://github.com/SettlerNVG/logchat/issues)
- [Releases](https://github.com/SettlerNVG/logchat/releases)

---

**Made with ❤️ for privacy-conscious users**
