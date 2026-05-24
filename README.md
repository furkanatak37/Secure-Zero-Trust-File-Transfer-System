# Secure Zero-Trust File Drop System

## CSE 4057 — Spring 2026 Programming Assignment

\---

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
python client/client.py upload   alice bob /path/to/file.txt --note "Secret note for bob"
python client/client.py upload   alice bob /path/to/large.bin --chunks   # force chunked upload
python client/client.py list     bob
python client/client.py download bob <file\_id>
python client/client.py revoke   alice <file\_id>
```

**Docker ile çalıştırma / Running with Docker:**

```bash
docker build -t secure-filedrop .
docker run --rm secure-filedrop          # full demo
docker compose up demo                   # docker-compose ile
```

**Tam Otomatik Demo / Full automated demo:**

```bash
python demo.py
```

\---

## System Design

### Components

|Component|Role|
|-|-|
|**CA** (`ca/ca.py`)|Certificate Authority — issues and signs X.509 certificates|
|**Server** (`server/server.py`)|Zero-trust relay — stores ciphertexts, enforces access control|
|**Client** (`client/client.py`)|User agent — encrypts/decrypts files, manages identities|
|**Common** (`common/`)|Shared crypto utilities and logger|

### Directory Structure

```
secure-filedrop/
├── ca/
│   ├── ca.py                  # CA server
│   ├── ca\_private\_key.pem     # (generated on first run)
│   └── ca\_cert.pem            # (generated on first run)
├── server/
│   ├── server.py              # Server main
│   ├── server\_private\_key.pem # (generated on first run)
│   ├── server\_cert.pem        # (generated on first run)
│   ├── storage/               # Encrypted file packages (JSON)
│   ├── db/filedrop.db         # SQLite metadata
│   └── logs/SERVER.log
├── client/
│   ├── client.py              # Client CLI
│   ├── identities/<user>/     # Per-user keys and certs
│   ├── downloads/             # Decrypted downloaded files
│   └── logs/CLIENT-\*.log
├── common/
│   ├── crypto\_utils.py        # All cryptographic primitives
│   └── logger.py              # Structured logging
├── demo.py                    # End-to-end demo
└── requirements.txt
```

\---

## Protocol Design

### 1\. Certificate Authority Protocol

**CSR Request (plaintext TCP, pre-trust phase):**

```
Client → CA:  RAW\_JSON { csr: <PEM>, identity: <str> }
CA → Client:  RAW\_JSON { certificate: <PEM>, ca\_cert: <PEM> }
```

All messages prefixed with a 4-byte big-endian length header.

### 2\. Client–Server Handshake

The handshake establishes **mutual authentication** and a **shared session key** without relying on SSL/TLS.

```
Client                              Server
  |                                   |
  |<── RAW\_JSON(cert\_s, nonce\_s) ─────|  (1) Server HELLO
  |─── RAW\_JSON(cert\_c, nonce\_c) ────>|  (2) Client HELLO
  |                                   |
  |      \[Both verify peer certificate against CA]
  |                                   |
  |<── RAW\_JSON(sign(nonce\_c)) ───────|  (3) Server AUTH proof
  |─── RAW\_JSON(sign(nonce\_s)) ──────>|  (4) Client AUTH proof
  |                                   |
  |      \[Both verify proof-of-possession]
  |                                   |
  |<── RAW\_JSON(ecdh\_pub\_s) ──────────|  (5) Server ECDH public key
  |─── RAW\_JSON(ecdh\_pub\_c) ─────────>|  (6) Client ECDH public key
  |                                   |
  |      \[Both compute ECDH shared secret]
  |      \[Both derive session keys via HKDF]
  |                                   |
  |<── RAW\_JSON(handshake\_complete) ──|  (7) Confirmation
  |                                   |
  |====== Encrypted session active ===|
```

**Proof-of-possession:** Each side signs the *other side's nonce* with their RSA private key.  
Verification uses the peer's certificate public key. A valid signature proves private key possession.

### 3\. Session Key Derivation (HKDF)

```python
key\_material = HKDF(
    algorithm = SHA-256,
    length    = 64 bytes,
    salt      = nonce\_client || nonce\_server,
    info      = b"secure-filedrop-session-v1"
).derive(ecdh\_shared\_secret)

c2s\_key = key\_material\[0:32]   # client encrypts → server decrypts
s2c\_key = key\_material\[32:64]  # server encrypts → client decrypts
```

### 4\. Message Framing (Post-Handshake)

All messages are AES-256-GCM encrypted:

```
\[4-byte length]\[12-byte nonce]\[AES-GCM ciphertext]
```

Plaintext (before encryption):

```json
{ "type": "...", "seq": 1, "timestamp": 1234567890.0, "payload": { ... } }
```

### 5\. File Upload Protocol

```
Client → Server: UPLOAD_REQUEST {
    file_id, sender_id, recipient_id,
    filename: "[confidential]",            ← always masked (Bonus 3)
    confidential_metadata: { nonce, ciphertext, encrypted_key },  ← encrypted filename/desc
    upload_time, expiration_time, file_hash,
    signature, request_nonce, sender_cert,
    encrypted_package: { nonce, ciphertext, encrypted_key }
                     | { chunked: true, total_chunks, manifest_hash,
                         encrypted_key, chunks: [{chunk_index, total_chunks,
                                                   nonce, ciphertext, chunk_hash}] },
    encrypted_note: { nonce, ciphertext, encrypted_key }  ← optional (Bonus 6)
}
Server → Client: ACK { file_id, status: "stored" }
                 or ERROR { message }
```

**Server verifications on upload:**

1. `request_nonce` freshness (replay protection).
2. `sender_id` matches authenticated identity.
3. Sender certificate valid against CA.
4. Digital signature over `sender|recipient|file_id|hash|ts|expiry`.
5. For regular packages: `file_hash` == SHA-256 of ciphertext. For chunked: `file_hash` == `manifest_hash`.

### 6\. File Encryption (End-to-End)

**Regular (< 64 KB):**
```
file_key   ← random 256-bit key
nonce      ← random 96-bit (12 bytes)
ciphertext ← AES-256-GCM(file_key, nonce, plaintext)
wrapped_key ← RSA-OAEP-SHA256(recipient_pub_key, file_key)

package = { nonce, ciphertext, encrypted_key: wrapped_key }
```

**Chunked (≥ 64 KB, Bonus 4):**
```
file_key     ← random 256-bit key (shared across all chunks)
wrapped_key  ← RSA-OAEP-SHA256(recipient_pub_key, file_key)

for each chunk[i]:
    nonce[i]      ← random 96-bit
    ciphertext[i] ← AES-256-GCM(file_key, nonce[i], chunk_data[i])
    chunk_hash[i] ← SHA-256(chunk_data[i])           ← plaintext chunk integrity

manifest_hash ← SHA-256( chunk_hash[0] | chunk_hash[1] | ... )   ← ordering integrity
file_hash     ← manifest_hash                         ← used in signature payload

package = { chunked: true, total_chunks, manifest_hash, encrypted_key,
            chunks: [{ chunk_index, nonce, ciphertext, chunk_hash }, ...] }
```

**Encrypted Note (Bonus 6):**
```
note_key    ← random 256-bit key
enc_note    ← AES-256-GCM(note_key, nonce, note_bytes)
wrapped_note_key ← RSA-OAEP-SHA256(recipient_pub_key, note_key)

encrypted_note = { nonce, ciphertext, encrypted_key: wrapped_note_key }
```

**Confidential Metadata (Bonus 3):**
```
meta_key   ← random 256-bit key
enc_meta   ← AES-256-GCM(meta_key, nonce, JSON({ filename, ... }))
wrapped_meta_key ← RSA-OAEP-SHA256(recipient_pub_key, meta_key)

confidential_metadata = { nonce, ciphertext, encrypted_key: wrapped_meta_key }
```

The server **never** sees `file_key`, plaintext contents, real filename, or note text. Only the recipient's RSA private key can unwrap any of these.

### 7\. Digital Signature

**Signed payload (canonical string):**

```
sender\_id | recipient\_id | file\_id | file\_hash | timestamp | expiration\_time
```

**Algorithm:** RSA-PSS with SHA-256, MGF1.

**When verified:**

* Server verifies on upload (authenticity + integrity before storage).
* Recipient verifies on download (origin authentication).

### 8\. File Retrieval Protocol

```
Client → Server: DOWNLOAD_REQUEST { file_id, request_nonce }
Server → Client: ACK { encrypted_package, signature, sender_id, file_hash,
                        upload_time, expiration_time,
                        confidential_metadata,  ← optional (Bonus 3)
                        encrypted_note }         ← optional (Bonus 6)
                 or ERROR { message }

Client-side post-download:
  1. Decrypt file_key with own RSA private key (RSA-OAEP).
  2a. Regular: decrypt file with AES-256-GCM; verify SHA-256(ciphertext) == file_hash.
  2b. Chunked: sort chunks → verify manifest_hash → decrypt each chunk →
               verify chunk_hash → concatenate (Bonus 4).
  3. Verify sender digital signature (RSA-PSS).
  4. Decrypt confidential_metadata → recover real filename (Bonus 3).
  5. Decrypt encrypted_note → display sender note (Bonus 6).
  6. Send RECIPIENT_ACK in a new authenticated session (Bonus 5).

Client → Server: RECIPIENT_ACK {
    recipient_id, file_id, ack_timestamp,
    signature = RSA-PSS(private_key, "ACK|recipient_id|file_id|ack_timestamp")
}
Server → Client: ACK { file_id, status: "ack_recorded" }
                 or ERROR { message }
```

\---

## Security Features

### Replay Protection

Replay attacks are prevented at two layers:

|Layer|Mechanism|
|-|-|
|Handshake|Fresh random nonces in each HELLO; proof signs the *peer's* nonce, making replays trivially detectable.|
|Application|Every UPLOAD/DOWNLOAD/REVOKE includes a `request\_nonce`. The server stores all seen nonces in SQLite (`used\_nonces` table) and rejects duplicates. Nonces older than 1 hour are purged.|

### Access Control

* File metadata includes `recipient\_id`.
* On download, server checks `authenticated\_client\_id == recipient\_id`.
* Mismatches are logged as unauthorized access attempts and rejected.

### File Expiration

* `expiration\_time` (Unix timestamp) is set by sender at upload.
* Server checks `expiration\_time < now` before every download.
* Expired files are marked `status = 'expired'` and excluded from `LIST\_FILES`.
* Expiration events are logged.

### Zero-Trust Storage

* Server stores `encrypted\_package` (ciphertext + AES nonce + RSA-wrapped key) in JSON files under `server/storage/`.
* Server never possesses `file\_key` (it is RSA-OAEP encrypted for the recipient).
* Server never sees plaintext file contents.

\---

## Cryptographic Choices

|Purpose|Algorithm|
|-|-|
|Long-term identity keys|RSA-2048|
|Key exchange|ECDH over P-256 (secp256r1)|
|Key derivation|HKDF-SHA256|
|Session encryption|AES-256-GCM|
|File encryption|AES-256-GCM (random per-file key)|
|File key wrapping|RSA-OAEP-SHA256|
|Digital signatures|RSA-PSS-SHA256|
|Certificate signing|X.509 v3, SHA256WithRSAEncryption|
|Integrity hashing|SHA-256|

\---

## Bonus Features Implemented

### 1. Revocation Before Download ✓

* Sender sends `REVOKE_REQUEST { file_id, request_nonce }`.
* Server checks `sender_id` matches authenticated user and file status is `pending`.
* File status updated to `revoked`; ciphertext deleted from disk.
* Any subsequent download attempt receives `file_status_revoked` error.
* Revocation events are logged.

### 2. One-Time Download ✓

* On successful download, server updates status to `downloaded`.
* Subsequent download attempts receive `file_status_downloaded` error.
* A download is only counted as "successful" when the server sends the ACK (full package delivered). Interrupted connections before the ACK do not consume the file — the status update happens at send-time, which is an acceptable design tradeoff documented here.

### 3. Confidential Metadata ✓

* The real filename (and any optional description) is **encrypted client-side** before upload using the same AES-GCM + RSA-OAEP scheme used for file content.
* The server stores only `filename = "[confidential]"` in its SQLite database — the actual filename is opaque to the server.
* The encrypted blob (`confidential_metadata`) is stored with the file package and forwarded to the recipient on download.
* Upon download, the recipient decrypts the blob with their private key to recover the original filename.
* **Fields visible to server:** `file_id`, `sender_id`, `recipient_id`, `upload_time`, `expiration_time`, `status`, `file_hash`, `signature` (all required for routing/access control).
* **Fields hidden from server:** `filename`, any future description fields.

### 4. Large File Chunking ✓

* Files larger than **64 KB** (configurable via `CHUNK_SIZE` in `crypto_utils.py`) are automatically split into fixed-size chunks.
* Each chunk is individually AES-GCM encrypted with the same per-file key; the file key is RSA-OAEP wrapped once for the recipient.
* Each chunk carries `chunk_index`, `total_chunks`, and `chunk_hash` (SHA-256 of the plaintext chunk).
* A **manifest hash** (SHA-256 over all ordered chunk hashes) enables detection of missing, reordered, duplicated, or modified chunks.
* On download, the receiver: (1) sorts by `chunk_index` and checks for gaps/duplicates; (2) verifies manifest hash; (3) decrypts each chunk and verifies its `chunk_hash`; (4) concatenates chunks to reconstruct the original file.

### 5. Recipient Acknowledgement ✓

* After successful download **and** signature verification, the client generates a signed ACK:  
  `payload = "ACK|<recipient_id>|<file_id>|<ack_timestamp>"` signed with RSA-PSS.
* The ACK is sent as a `RECIPIENT_ACK` message in a **new authenticated session** (full handshake), ensuring the ACK is tied to the authenticated identity.
* The server verifies the ACK comes from the intended recipient and the signature is valid against their CA-signed certificate.
* `ack_timestamp` and `ack_signature` are stored in the SQLite database for auditability.

### 6. End-to-End Encrypted Notes ✓

* The sender may attach a short note using `--note "text"` (CLI) or the `note=` parameter (API).
* The note is AES-GCM encrypted with a fresh 256-bit key, which is RSA-OAEP wrapped for the recipient — the server cannot read it.
* The encrypted note blob is stored by the server opaquely and forwarded together with the encrypted file, binding it to the same transfer context.
* On download, the recipient decrypts the note with their private key and it is displayed.

### 7. Containerized Deployment ✓

* A `Dockerfile` (Python 3.12-slim base) is provided. Build and run:
  ```bash
  docker build -t secure-filedrop .
  docker run --rm secure-filedrop        # runs the full demo
  ```
* A `docker-compose.yml` provides two modes:
  - **`demo` service**: runs `demo.py` (CA + Server + Clients in one container, no ports needed).
  - **`server` service** (profile `server-only`): persistent server with named volumes, accessible on port 9001.
  ```bash
  docker compose up demo
  docker compose --profile server-only up server
  ```
* Named volumes (`filedrop-data`, `filedrop-db`, `filedrop-logs`) persist storage, database, and logs across container restarts.

## Logging

Log files are written to:

* `ca/logs/CA.log`
* `server/logs/SERVER.log`
* `client/logs/CLIENT-<username>.log`

**Events logged (with timestamps):**

* Certificate issuance and verification results
* Handshake start, authentication success/failure
* Upload: storage confirmation, signature failures, hash mismatches, chunked mode info
* Download: success, access denied, expiration, revoked/downloaded status
* Confidential metadata decryption (Bonus 3)
* Chunked reassembly info: chunk count (Bonus 4)
* Recipient ACK: receipt, signature verification result, storage (Bonus 5)
* Encrypted note decryption (Bonus 6)
* Replay detection (nonce reuse)
* Revocation events

**Not logged:** Private keys, plaintext file contents, decrypted session keys, note contents, real filenames (server side).

\---

## Security Analysis \& Limitations

### Possible Vulnerabilities

**1. Man-in-the-Middle During Handshake**  
*Scenario:* Attacker intercepts the TCP connection and relays modified HELLO messages.  
*Mitigation:* Both sides verify the peer's certificate against the CA. Proof-of-possession (signing the peer's nonce) prevents an attacker from forwarding a certificate they don't own. A full MITM would require a fake CA-signed certificate, which requires compromising the CA.  
*Residual risk:* CA private key compromise would undermine all trust.

**2. CA Private Key Compromise**  
*Scenario:* Attacker obtains `ca/ca\_private\_key.pem` and issues fraudulent certificates.  
*Countermeasure:* In production, store CA key in an HSM; use an offline CA. Implement certificate revocation lists (CRL) or OCSP.

**3. Weak Randomness**  
*Scenario:* If `os.urandom()` is not cryptographically secure on the platform, nonces and keys may be predictable.  
*Mitigation:* Python's `os.urandom()` is backed by the OS CSPRNG (e.g., `/dev/urandom` on Linux). Acceptable for this context.

**4. Replay of Encrypted Session Messages**  
*Scenario:* An attacker records and replays an encrypted `DOWNLOAD\_REQUEST`.  
*Mitigation:* Each request includes a fresh `request\_nonce`. The server stores and deduplicates nonces. The one-time download feature also prevents replayed downloads.  
*Residual risk:* Nonce table is in-memory-bounded to 1 hour; nonces valid within that window are safely rejected.

**5. Metadata Leakage**  
*Scenario:* Server knows `sender\_id`, `recipient\_id`, `filename`, `upload\_time`, `expiration\_time`.  
*Mitigation (implemented):* Sensitive fields (filename, description) are encrypted client-side as part of the Confidential Metadata bonus feature. The server only stores `"[confidential]"` as the filename. Fields required for routing (`recipient_id`, `file_id`, `status`) remain visible to the server as unavoidable.

**6. Timing Attacks on Signature Verification**  
*Scenario:* An attacker uses timing differences during `verify\_signature` to learn information.  
*Mitigation:* Python's `cryptography` library uses constant-time comparisons for signature verification internally.

**7. Log File Leakage**  
*Scenario:* Log files expose metadata (who sent what to whom, when).  
*Countermeasure:* Restrict log file permissions; use log aggregation with access control. Never log ciphertext content.

**8. Concurrent Download Race Condition**  
*Scenario:* Two simultaneous download requests from the same client could both succeed before the status update.  
*Mitigation:* In this implementation, SQLite provides serialized writes. A production system should use `SELECT FOR UPDATE` or a distributed lock.

\---

## Division of Labor

|Member|Implemented|
|-|-|
|Muhammed Furkan Atak |CA, PKI, certificate issuance, Expiration|
|Cihat Emre Vardiş|Handshake, ECDH, HKDF, session keys, revocation|
|Ömer Can Şimşek|File encryption, upload, download, access control, logging|

**Communication: Send message to** https://www.linkedin.com/in/furkanatak/  
**Integration:** Developed on separate branches, merged via pull requests with code review.

\---

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
python client/client.py download bob <file\_id\_from\_list>
```

