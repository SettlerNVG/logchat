# LogMessager Protocol Specification

## Overview

This document describes the communication protocols used in LogMessager.

## gRPC Services

### Central Server Services

#### AuthService

```protobuf
service AuthService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Login(LoginRequest) returns (LoginResponse);
  rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
  rpc Logout(LogoutRequest) returns (LogoutResponse);
}
```

#### UserService

```protobuf
service UserService {
  rpc GetUser(GetUserRequest) returns (GetUserResponse);
  rpc GetPublicKey(GetPublicKeyRequest) returns (GetPublicKeyResponse);
  rpc UpdatePresence(UpdatePresenceRequest) returns (UpdatePresenceResponse);
  rpc ListOnlineUsers(ListOnlineUsersRequest) returns (ListOnlineUsersResponse);
  rpc SearchUsers(SearchUsersRequest) returns (SearchUsersResponse);
  rpc SubscribePresence(SubscribePresenceRequest) returns (stream PresenceUpdate);
}
```

#### SessionService

```protobuf
service SessionService {
  rpc RequestChat(RequestChatRequest) returns (RequestChatResponse);
  rpc AcceptChat(AcceptChatRequest) returns (AcceptChatResponse);
  rpc DeclineChat(DeclineChatRequest) returns (DeclineChatResponse);
  rpc EndSession(EndSessionRequest) returns (EndSessionResponse);
  rpc ReportHostReady(ReportHostReadyRequest) returns (ReportHostReadyResponse);
  rpc SubscribeSessionEvents(SubscribeSessionEventsRequest) returns (stream SessionEvent);
}
```

### P2P Service (runs on host peer)

#### ChatService

```protobuf
service ChatService {
  rpc Handshake(HandshakeRequest) returns (HandshakeResponse);
  rpc Stream(stream ChatMessage) returns (stream ChatMessage);
}
```

## Authentication

### JWT Token Structure

```json
{
  "user_id": "uuid",
  "username": "string",
  "exp": 1234567890,
  "iat": 1234567890,
  "iss": "logmessager"
}
```

### Token Lifecycle

- Access Token: 15 minutes
- Refresh Token: 7 days

### Authorization Header

```
Authorization: Bearer <access_token>
```

## Cryptographic Handshake

### Step 1: Client sends HandshakeRequest

```protobuf
message HandshakeRequest {
  string session_token = 1;       // From SessionService
  bytes ephemeral_public_key = 2; // Curve25519
  bytes signature = 3;            // Ed25519 signature
}
```

Signature covers: `session_token || ephemeral_public_key`

### Step 2: Host verifies and responds

```protobuf
message HandshakeResponse {
  bool success = 1;
  bytes ephemeral_public_key = 2;
  bytes signature = 3;
  string error = 4;
}
```

### Step 3: Key Derivation

Both parties compute:

```
shared_secret = ECDH(my_ephemeral_private, peer_ephemeral_public)
keys = HKDF-SHA256(shared_secret, salt=nil, info="logmessager-session-keys")
send_key = keys[0:32]
recv_key = keys[32:64]
```

Note: Initiator and responder swap send/recv keys.

## Message Format

### ChatMessage

```protobuf
message ChatMessage {
  MessageType type = 1;
  bytes payload = 2;    // Encrypted
  bytes nonce = 3;      // 12 bytes for AES-GCM
  int64 timestamp = 4;
  string message_id = 5;
}
```

### Encryption

```
ciphertext = AES-GCM-Encrypt(
  key = send_key,
  nonce = random(12),
  plaintext = serialize(payload),
  aad = nil
)
```

### Message Types

| Type | Description |
|------|-------------|
| TEXT | Regular text message |
| TYPING | User is typing |
| STOP_TYPING | User stopped typing |
| ACK | Message acknowledgment |
| HEARTBEAT | Keep-alive |
| DISCONNECT | Graceful disconnect |

## Session Lifecycle

### State Machine

```
                    ┌─────────────┐
                    │   IDLE      │
                    └──────┬──────┘
                           │ RequestChat
                           ▼
                    ┌─────────────┐
         Decline    │   PENDING   │
        ┌───────────┤             │
        │           └──────┬──────┘
        │                  │ Accept
        ▼                  ▼
┌─────────────┐     ┌─────────────┐
│  DECLINED   │     │  ACCEPTED   │
└─────────────┘     └──────┬──────┘
                           │ Host Ready
                           ▼
                    ┌─────────────┐
                    │ CONNECTING  │
                    └──────┬──────┘
                           │ Handshake Complete
                           ▼
                    ┌─────────────┐
                    │   ACTIVE    │◄──── Messages
                    └──────┬──────┘
                           │ End/Disconnect
                           ▼
                    ┌─────────────┐
                    │   ENDED     │
                    └─────────────┘
```

## Error Codes

| Code | Description |
|------|-------------|
| UNAUTHENTICATED | Invalid or missing token |
| NOT_FOUND | User or session not found |
| ALREADY_EXISTS | Username taken |
| FAILED_PRECONDITION | User offline, already in session |
| INVALID_ARGUMENT | Bad request parameters |

## Heartbeat Protocol

- Interval: 30 seconds
- Timeout: 90 seconds (3 missed heartbeats)

```protobuf
message HeartbeatPayload {
  int64 timestamp = 1;
}
```

## Presence Updates

Clients should call `UpdatePresence` on:
- Login (is_online = true)
- Logout (is_online = false)
- Network change (update nat_type, public_address)
- Periodic refresh (every 5 minutes)
