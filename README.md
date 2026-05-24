# Secure Zero-Trust File Drop System
## CSE 4057 — Spring 2026 Programming Assignment

---

## Kurulum / Setup

```bash
pip install -r requirements.txt
```

## Çalıştırma / Running

**Terminal 1 — CA:**
```bash
python ca/ca.py
```

**Terminal 2 — Server:**
```bash
python server/server.py
```

**Terminal 3+ — Clients:**
```bash
python client/client.py register alice
python client/client.py register bob
python client/client.py upload   alice bob /path/to/file.txt
python client/client.py list     bob
python client/client.py download bob <file_id>
python client/client.py revoke   alice <file_id>
```

**Tam Otomatik Demo / Full automated demo:**
```bash
python demo.py
```

---

## System Design

### Components

| Component | Role |
|-----------|------|
| **CA** (`ca/ca.py`) | Certificate Authority — issues and signs X.509 certificates |
| **Server** (`server/server.py`) | Zero-trust relay — stores ciphertexts, enforces access control |
| **Client** (`client/client.py`) | User agent — encrypts/decrypts files, manages identities |
| **Common** (`common/`) | Shared crypto utilities and logger |

### Directory Structure
```
secure-filedrop/
├── ca/
│   ├── ca.py                  # CA server
│   ├── ca_private_key.pem     # (generated on first run)
│   └── ca_cert.pem            # (generated on first run)
├── server/
│   ├── server.py              # Server main
│   ├── server_private_key.pem # (generated on first run)
│   ├── server_cert.pem        # (generated on first run)
│   ├── storage/               # Encrypted file packages (JSON)
│   ├── db/filedrop.db         # SQLite metadata
│   └── logs/SERVER.log
├── client/
│   ├── client.py              # Client CLI
│   ├── identities/<user>/     # Per-user keys and certs
│   ├── downloads/             # Decrypted downloaded files
│   └── logs/CLIENT-*.log
├── common/
│   ├── crypto_utils.py        # All cryptographic primitives
│   └── logger.py              # Structured logging
├── demo.py                    # End-to-end demo
└── requirements.txt
```

---

## Protocol Design

### 1. Certificate Authority Protocol

**CSR Request (plaintext TCP, pre-trust phase):**
```
Client → CA:  RAW_JSON { csr: <PEM>, identity: <str> }
CA → Client:  RAW_JSON { certificate: <PEM>, ca_cert: <PEM> }
```

All messages prefixed with a 4-byte big-endian length header.

### 2. Client–Server Handshake

The handshake establishes **mutual authentication** and a **shared session key** without relying on SSL/TLS.

```
Client                              Server
  |                                   |
  |<── RAW_JSON(cert_s, nonce_s) ─────|  (1) Server HELLO
  |─── RAW_JSON(cert_c, nonce_c) ────>|  (2) Client HELLO
  |                                   |
  |      [Both verify peer certificate against CA]
  |                                   |
  |<── RAW_JSON(sign(nonce_c)) ───────|  (3) Server AUTH proof
  |─── RAW_JSON(sign(nonce_s)) ──────>|  (4) Client AUTH proof
  |                                   |
  |      [Both verify proof-of-possession]
  |                                   |
  |<── RAW_JSON(ecdh_pub_s) ──────────|  (5) Server ECDH public key
  |─── RAW_JSON(ecdh_pub_c) ─────────>|  (6) Client ECDH public key
  |                                   |
  |      [Both compute ECDH shared secret]
  |      [Both derive session keys via HKDF]
  |                                   |
  |<── RAW_JSON(handshake_complete) ──|  (7) Confirmation
  |                                   |
  |====== Encrypted session active ===|
```

**Proof-of-possession:** Each side signs the *other side's nonce* with their RSA private key.  
Verification uses the peer's certificate public key. A valid signature proves private key possession.

### 3. Session Key Derivation (HKDF)

```python
key_material = HKDF(
    algorithm = SHA-256,
    length    = 64 bytes,
    salt      = nonce_client || nonce_server,
    info      = b"secure-filedrop-session-v1"
).derive(ecdh_shared_secret)

c2s_key = key_material[0:32]   # client encrypts → server decrypts
s2c_key = key_material[32:64]  # server encrypts → client decrypts
```

### 4. Message Framing (Post-Handshake)

All messages are AES-256-GCM encrypted:
```
[4-byte length][12-byte nonce][AES-GCM ciphertext]
```
Plaintext (before encryption):
```json
{ "type": "...", "seq": 1, "timestamp": 1234567890.0, "payload": { ... } }
```

### 5. File Upload Protocol

```
Client → Server: UPLOAD_REQUEST {
    file_id, sender_id, recipient_id, filename,
    upload_time, expiration_time, file_hash,
    signature, request_nonce, sender_cert,
    encrypted_package: { nonce, ciphertext, encrypted_key }
}
Server → Client: ACK { file_id, status: "stored" }
                 or ERROR { message }
```

**Server verifications on upload:**
1. `request_nonce` freshness (replay protection).
2. `sender_id` matches authenticated identity.
3. Sender certificate valid against CA.
4. Digital signature over `sender|recipient|file_id|hash|ts|expiry`.
5. `file_hash` matches SHA-256 of the ciphertext.

### 6. File Encryption (End-to-End)

```
file_key  ← random 256-bit key
nonce     ← random 96-bit (12 bytes)
ciphertext ← AES-256-GCM(file_key, nonce, plaintext)
wrapped_key ← RSA-OAEP-SHA256(recipient_pub_key, file_key)

uploaded_package = { nonce, ciphertext, encrypted_key: wrapped_key }
```

The server **never** sees `file_key` or the plaintext. Only the recipient's RSA private key can unwrap `file_key`.

### 7. Digital Signature

**Signed payload (canonical string):**
```
sender_id | recipient_id | file_id | file_hash | timestamp | expiration_time
```

**Algorithm:** RSA-PSS with SHA-256, MGF1.

**When verified:**
- Server verifies on upload (authenticity + integrity before storage).
- Recipient verifies on download (origin authentication).

### 8. File Retrieval Protocol

```
Client → Server: DOWNLOAD_REQUEST { file_id, request_nonce }
Server → Client: ACK { encrypted_package, signature, sender_id, file_hash, expiration_time }
                 or ERROR { message }

Client-side post-download:
  1. Decrypt file_key with own RSA private key (RSA-OAEP).
  2. Decrypt file with AES-256-GCM.
  3. Verify SHA-256 of ciphertext == server-reported file_hash.
  4. Verify sender digital signature.
```

---

## Security Features

### Replay Protection

Replay attacks are prevented at two layers:

| Layer | Mechanism |
|-------|-----------|
| Handshake | Fresh random nonces in each HELLO; proof signs the *peer's* nonce, making replays trivially detectable. |
| Application | Every UPLOAD/DOWNLOAD/REVOKE includes a `request_nonce`. The server stores all seen nonces in SQLite (`used_nonces` table) and rejects duplicates. Nonces older than 1 hour are purged. |

### Access Control

- File metadata includes `recipient_id`.
- On download, server checks `authenticated_client_id == recipient_id`.
- Mismatches are logged as unauthorized access attempts and rejected.

### File Expiration

- `expiration_time` (Unix timestamp) is set by sender at upload.
- Server checks `expiration_time < now` before every download.
- Expired files are marked `status = 'expired'` and excluded from `LIST_FILES`.
- Expiration events are logged.

### Zero-Trust Storage

- Server stores `encrypted_package` (ciphertext + AES nonce + RSA-wrapped key) in JSON files under `server/storage/`.
- Server never possesses `file_key` (it is RSA-OAEP encrypted for the recipient).
- Server never sees plaintext file contents.

---

## Cryptographic Choices

| Purpose | Algorithm |
|---------|-----------|
| Long-term identity keys | RSA-2048 |
| Key exchange | ECDH over P-256 (secp256r1) |
| Key derivation | HKDF-SHA256 |
| Session encryption | AES-256-GCM |
| File encryption | AES-256-GCM (random per-file key) |
| File key wrapping | RSA-OAEP-SHA256 |
| Digital signatures | RSA-PSS-SHA256 |
| Certificate signing | X.509 v3, SHA256WithRSAEncryption |
| Integrity hashing | SHA-256 |

---

## Bonus Features Implemented

### 1. Revocation Before Download ✓
- Sender sends `REVOKE_REQUEST { file_id, request_nonce }`.
- Server checks sender_id matches authenticated user and file status is `pending`.
- File status updated to `revoked`; ciphertext deleted from disk.
- Any subsequent download attempt receives `file_status_revoked` error.
- Revocation events are logged.

### 2. One-Time Download ✓
- On successful download, server updates status to `downloaded`.
- Subsequent download attempts receive `file_status_downloaded` error.
- A download is only counted as "successful" when the server sends the ACK (i.e., the full package is delivered). Interrupted connections before ACK do not consume the file (the status update happens at send-time, which is an acceptable design tradeoff documented here).

---

## Logging

Log files are written to:
- `ca/logs/CA.log`
- `server/logs/SERVER.log`
- `client/logs/CLIENT-<username>.log`

**Events logged (with timestamps):**
- Certificate issuance and verification results
- Handshake start, authentication success/failure
- Upload: storage confirmation, signature failures, hash mismatches
- Download: success, access denied, expiration, revoked status
- Replay detection
- Revocation events

**Not logged:** Private keys, plaintext file contents, decrypted session keys.

---

## Security Analysis & Limitations

### Possible Vulnerabilities

**1. Man-in-the-Middle During Handshake**  
*Scenario:* Attacker intercepts the TCP connection and relays modified HELLO messages.  
*Mitigation:* Both sides verify the peer's certificate against the CA. Proof-of-possession (signing the peer's nonce) prevents an attacker from forwarding a certificate they don't own. A full MITM would require a fake CA-signed certificate, which requires compromising the CA.  
*Residual risk:* CA private key compromise would undermine all trust.

**2. CA Private Key Compromise**  
*Scenario:* Attacker obtains `ca/ca_private_key.pem` and issues fraudulent certificates.  
*Countermeasure:* In production, store CA key in an HSM; use an offline CA. Implement certificate revocation lists (CRL) or OCSP.

**3. Weak Randomness**  
*Scenario:* If `os.urandom()` is not cryptographically secure on the platform, nonces and keys may be predictable.  
*Mitigation:* Python's `os.urandom()` is backed by the OS CSPRNG (e.g., `/dev/urandom` on Linux). Acceptable for this context.

**4. Replay of Encrypted Session Messages**  
*Scenario:* An attacker records and replays an encrypted `DOWNLOAD_REQUEST`.  
*Mitigation:* Each request includes a fresh `request_nonce`. The server stores and deduplicates nonces. The one-time download feature also prevents replayed downloads.  
*Residual risk:* Nonce table is in-memory-bounded to 1 hour; nonces valid within that window are safely rejected.

**5. Metadata Leakage**  
*Scenario:* Server knows `sender_id`, `recipient_id`, `filename`, `upload_time`, `expiration_time`.  
*Note:* This is unavoidable for routing/access-control purposes. Sensitive fields (filename, description) could be encrypted client-side as a bonus feature (not fully implemented).

**6. Timing Attacks on Signature Verification**  
*Scenario:* An attacker uses timing differences during `verify_signature` to learn information.  
*Mitigation:* Python's `cryptography` library uses constant-time comparisons for signature verification internally.

**7. Log File Leakage**  
*Scenario:* Log files expose metadata (who sent what to whom, when).  
*Countermeasure:* Restrict log file permissions; use log aggregation with access control. Never log ciphertext content.

**8. Concurrent Download Race Condition**  
*Scenario:* Two simultaneous download requests from the same client could both succeed before the status update.  
*Mitigation:* In this implementation, SQLite provides serialized writes. A production system should use `SELECT FOR UPDATE` or a distributed lock.

---

## Division of Labor

*(Fill in for group submission)*

| Member | Implemented |
|--------|-------------|
| — | CA, PKI, certificate issuance |
| — | Handshake, ECDH, HKDF, session keys |
| — | File encryption, upload, download, access control |
| — | Expiration, revocation, logging, README, demo |

**Communication:** Used [describe: Discord/WhatsApp/etc.]  
**Integration:** Developed on separate branches, merged via pull requests with code review.

---

## How to Run Tests

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run full automated demo (starts CA + server internally)
python demo.py

# 3. Or run components manually:
# Terminal 1
python ca/ca.py

# Terminal 2
python server/server.py

# Terminal 3
python client/client.py register alice
python client/client.py register bob
python client/client.py upload alice bob /tmp/test.txt
python client/client.py list bob
python client/client.py download bob <file_id_from_list>
```
