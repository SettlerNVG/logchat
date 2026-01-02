# LogChat Architecture

## Overview

LogChat is a secure, ephemeral messaging system designed with privacy as the primary concern. The architecture ensures that message content never touches the central server.

## Components

### Central Server

The central server handles:
- User registration and authentication
- Public key storage
- Presence management (online/offline status)
- Session coordination (who chats with whom)
- Host selection for P2P connections

**The server explicitly does NOT:**
- Store messages
- Participate in message relay
- Have access to encryption keys

### Client

Each client can operate in two modes:
- **Host Mode**: Runs a temporary gRPC server to accept peer connections
- **Client Mode**: Connects to a peer's host server

## Data Flow

### Registration

```
Client                          Server                    Database
  │                               │                          │
  │──Register(user, pass, pk)────►│                          │
  │                               │──INSERT user, pk────────►│
  │                               │◄─────────────────────────│
  │◄──────────{user_id}───────────│                          │
```

### Chat Initiation

```
Client A              Server              Client B
   │                    │                    │
   │──RequestChat(B)───►│                    │
   │                    │──ChatRequest──────►│
   │                    │                    │
   │                    │◄──AcceptChat───────│
   │                    │                    │
   │                    │ [Determine Host]   │
   │                    │                    │
   │◄─SessionInfo(host)─│─SessionInfo(host)─►│
   │                    │                    │
```

### P2P Connection (A = Host)

```
Client A (Host)                              Client B (Client)
     │                                             │
     │◄────────────gRPC Connect────────────────────│
     │                                             │
     │◄────Handshake(ephemeral_pk, signature)──────│
     │                                             │
     │──Handshake(ephemeral_pk, signature)────────►│
     │                                             │
     │         [Both compute shared secret]        │
     │         [Derive session keys]               │
     │                                             │
     │◄═══════Encrypted Bidirectional Stream══════►│
```

## Security Architecture

### Key Hierarchy

```
Identity Key (Curve25519)
    │
    └── Stored on device, public key on server
    │
    └── Used to sign handshakes
    
Ephemeral Key (Curve25519)
    │
    └── Generated per session
    │
    └── Used for Diffie-Hellman key exchange
    
Session Key (AES-256)
    │
    └── Derived from DH shared secret via HKDF
    │
    └── Destroyed when session ends
```

### Encryption Flow

```
Plaintext Message
       │
       ▼
┌──────────────┐
│  Serialize   │
│  (protobuf)  │
└──────────────┘
       │
       ▼
┌──────────────┐
│   AES-GCM    │
│   Encrypt    │
│ (session key)│
└──────────────┘
       │
       ▼
┌──────────────┐
│  gRPC Send   │
│  (over TLS)  │
└──────────────┘
```

## Database Schema

```sql
users
├── id (UUID, PK)
├── username (UNIQUE)
├── password_hash
└── created_at

public_keys
├── id (UUID, PK)
├── user_id (FK → users)
├── key_type
└── public_key (BYTEA)

user_presence
├── user_id (PK, FK → users)
├── is_online
├── nat_type
├── can_accept_inbound
└── public_address

sessions (metadata only)
├── id (UUID, PK)
├── initiator_id (FK → users)
├── responder_id (FK → users)
├── host_id (FK → users)
├── started_at
├── ended_at
└── end_reason
```

## Network Considerations

### NAT Types

| NAT Type | Can Host | Can Connect |
|----------|----------|-------------|
| None (Public IP) | ✅ | ✅ |
| Full Cone | ✅ | ✅ |
| Restricted | ⚠️ | ✅ |
| Symmetric | ❌ | ✅ |

### Host Selection Algorithm

```go
func selectHost(initiator, responder Presence) (hostID, error) {
    if initiator.CanAcceptInbound {
        return initiator.UserID, nil
    }
    if responder.CanAcceptInbound {
        return responder.UserID, nil
    }
    return nil, ErrNoConnectionPath
}
```

## Failure Modes

| Scenario | Behavior |
|----------|----------|
| Server down | Cannot start new chats, active P2P chats continue |
| Host disconnects | Session ends, keys destroyed |
| Client disconnects | Session ends, keys destroyed |
| Network interruption | Heartbeat timeout → session ends |

## Future Considerations

### TURN Relay (Not in MVP)

For cases where both users are behind symmetric NAT:

```
Client A ◄──► TURN Server ◄──► Client B
```

This would require:
- TURN server infrastructure
- Credential management
- Bandwidth considerations
