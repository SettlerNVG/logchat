# LogChat

Secure P2P terminal messenger with end-to-end encryption.

Messages exist only in RAM during chat session — nothing is stored on servers or disk.

## Features

- **End-to-End Encryption** — Curve25519 + AES-256-GCM
- **Peer-to-Peer** — Direct connection between users
- **No Message Storage** — Messages only in RAM, destroyed when chat ends
- **Terminal UI** — Clean TUI interface

## Tech Stack

- **Go 1.22+**
- **gRPC** — Server communication
- **Protocol Buffers** — Message serialization
- **Bubbletea** — Terminal UI framework
- **PostgreSQL** — User data only (no messages)
- **Docker** — Server deployment

## Install

```bash
curl -sSL https://raw.githubusercontent.com/SettlerNVG/logchat/main/install.sh | bash
```

Or download from [Releases](https://github.com/SettlerNVG/logchat/releases).

## Usage

```bash
logchat
```

## Architecture

```
┌─────────────────────────────────────────┐
│           CENTRAL SERVER                │
│    (Auth, Contacts, Coordination)       │
│         ❌ NO MESSAGE STORAGE           │
└─────────────────────────────────────────┘
                    │
              Coordination
                    │
     ┌──────────────┴──────────────┐
     │                             │
┌────▼────┐                   ┌────▼────┐
│ User A  │◄══════ P2P ══════►│ User B  │
│ [HOST]  │   E2EE Messages   │[CLIENT] │
└─────────┘                   └─────────┘
```

## Security

- Transport: TLS (planned)
- Key Exchange: Curve25519 ECDH
- Encryption: AES-256-GCM
- Session keys destroyed when chat ends

## License

MIT
