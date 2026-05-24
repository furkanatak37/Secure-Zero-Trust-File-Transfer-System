"""
Secure File Drop — Server

Responsibilities:
  - Obtain CA-signed certificate on first run.
  - Accept client connections and perform mutual TLS-like handshake.
  - Enforce access control: only intended recipient can download a file.
  - Store encrypted file packages on disk (zero-trust: never sees plaintext).
  - Track metadata in SQLite.
  - Enforce file expiration.
  - Log all security-relevant events.

Handshake (per connection):
  1. Exchange HELLO (cert + nonce).
  2. Exchange AUTH (sign peer's nonce → prove private-key possession).
  3. ECDH key exchange → derive session keys via HKDF.
  4. All subsequent messages encrypted with AES-GCM session keys.

Message types (after handshake):
  UPLOAD_REQUEST  → client sends file package for a recipient
  LIST_FILES      → client requests its pending files
  DOWNLOAD_REQUEST→ client requests a specific file
  REVOKE_REQUEST  → sender revokes a not-yet-downloaded file
  ACK             → generic acknowledgement
  ERROR           → error response
"""

import os
import sys
import json
import socket
import threading
import time
import sqlite3
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import serialization

from common.crypto_utils import (
    generate_rsa_keypair, generate_ec_keypair,
    serialize_private_key, load_private_key,
    serialize_public_key, load_public_key,
    serialize_cert, load_cert,
    create_csr, serialize_csr,
    sign_data, verify_signature,
    ecdh_shared_secret, derive_session_keys,
    generate_nonce, generate_file_id, sha256_hash,
    build_signature_payload,
    send_message, recv_message, send_raw, recv_raw
)
from common.logger import get_logger
from ca.ca import request_certificate

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001
SERVER_ID = "server"
BASE_DIR = os.path.dirname(__file__)
KEY_FILE = os.path.join(BASE_DIR, "server_private_key.pem")
CERT_FILE = os.path.join(BASE_DIR, "server_cert.pem")
CA_CERT_FILE = os.path.join(BASE_DIR, "ca_cert.pem")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
DB_FILE = os.path.join(BASE_DIR, "db", "filedrop.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")

logger = get_logger("SERVER", LOG_DIR)

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            file_id         TEXT PRIMARY KEY,
            sender_id       TEXT NOT NULL,
            recipient_id    TEXT NOT NULL,
            filename        TEXT NOT NULL,
            upload_time     REAL NOT NULL,
            expiration_time REAL NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            file_hash       TEXT NOT NULL,
            signature       TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS used_nonces (
            nonce TEXT PRIMARY KEY,
            ts    REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def db_insert_file(meta: dict):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO files
            (file_id, sender_id, recipient_id, filename, upload_time,
             expiration_time, status, file_hash, signature)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        meta["file_id"], meta["sender_id"], meta["recipient_id"],
        meta["filename"], meta["upload_time"], meta["expiration_time"],
        "pending", meta["file_hash"], meta["signature"]
    ))
    conn.commit()
    conn.close()


def db_get_file(file_id: str):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def db_list_pending(recipient_id: str):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM files WHERE recipient_id=? AND status='pending'", (recipient_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def db_update_status(file_id: str, status: str):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("UPDATE files SET status=? WHERE file_id=?", (status, file_id))
    conn.commit()
    conn.close()


def db_check_nonce(nonce: str) -> bool:
    """Returns True if nonce is fresh (not seen before)."""
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT nonce FROM used_nonces WHERE nonce=?", (nonce,)).fetchone()
    if row:
        conn.close()
        return False
    conn.execute("INSERT INTO used_nonces (nonce, ts) VALUES (?,?)", (nonce, time.time()))
    # Purge nonces older than 1 hour
    conn.execute("DELETE FROM used_nonces WHERE ts < ?", (time.time() - 3600,))
    conn.commit()
    conn.close()
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Server identity management
# ─────────────────────────────────────────────────────────────────────────────

class ServerIdentity:
    def __init__(self):
        self.private_key, self.public_key = self._load_or_create_keys()
        self.certificate, self.ca_cert = self._load_or_obtain_cert()

    def _load_or_create_keys(self):
        if os.path.exists(KEY_FILE):
            logger.info("Loading existing server key from %s", KEY_FILE)
            with open(KEY_FILE, "rb") as f:
                pk = load_private_key(f.read())
            return pk, pk.public_key()
        logger.info("Generating server RSA-2048 key pair …")
        pk, pub = generate_rsa_keypair(2048)
        with open(KEY_FILE, "wb") as f:
            f.write(serialize_private_key(pk))
        return pk, pub

    def _load_or_obtain_cert(self):
        if os.path.exists(CERT_FILE) and os.path.exists(CA_CERT_FILE):
            logger.info("Loading existing server certificate …")
            with open(CERT_FILE, "rb") as f:
                cert = load_cert(f.read())
            with open(CA_CERT_FILE, "rb") as f:
                ca_cert = load_cert(f.read())
            return cert, ca_cert

        logger.info("Requesting certificate from CA …")
        csr = create_csr(self.private_key, SERVER_ID)
        cert_pem, ca_cert_pem = request_certificate(SERVER_ID, serialize_csr(csr))
        cert = load_cert(cert_pem)
        ca_cert = load_cert(ca_cert_pem)
        with open(CERT_FILE, "wb") as f:
            f.write(cert_pem)
        with open(CA_CERT_FILE, "wb") as f:
            f.write(ca_cert_pem)
        logger.info("Server certificate obtained and saved.")
        return cert, ca_cert


# ─────────────────────────────────────────────────────────────────────────────
# Certificate verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_cert_against_ca(cert, ca_cert) -> bool:
    """Verify cert was signed by the CA."""
    try:
        import datetime
        from cryptography.hazmat.primitives.asymmetric import padding
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        now = datetime.datetime.utcnow()
        if not (cert.not_valid_before_utc.replace(tzinfo=None) <= now <=
                cert.not_valid_after_utc.replace(tzinfo=None)):
            return False
        return True
    except Exception:
        return False


def get_cn(cert) -> str:
    from cryptography.x509.oid import NameOID
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


# ─────────────────────────────────────────────────────────────────────────────
# Client handler (one per connection)
# ─────────────────────────────────────────────────────────────────────────────

class ClientHandler:
    def __init__(self, conn, addr, identity: ServerIdentity):
        self.conn = conn
        self.addr = addr
        self.identity = identity
        self.client_id = None
        self.c2s_key = None  # client → server decrypt key
        self.s2c_key = None  # server → client encrypt key
        self.seq = 0

    def _next_seq(self):
        self.seq += 1
        return self.seq

    def _send(self, msg_type, payload):
        send_message(self.conn, self.s2c_key, msg_type, payload, self._next_seq())

    def _recv(self):
        return recv_message(self.conn, self.c2s_key)

    # ── Handshake ───────────────────────────────────────────────────────────

    def handshake(self) -> bool:
        """
        Perform mutual-authenticated ECDH handshake.
        Returns True on success.
        """
        try:
            # 1. Exchange HELLOs
            server_nonce = generate_nonce()
            server_hello = {
                "cert": serialize_cert(self.identity.certificate).decode(),
                "nonce": server_nonce.hex()
            }
            send_raw(self.conn, json.dumps(server_hello).encode())

            raw = recv_raw(self.conn)
            if not raw:
                return False
            client_hello = json.loads(raw.decode())
            client_cert_pem = client_hello["cert"].encode()
            client_nonce = bytes.fromhex(client_hello["nonce"])

            # 2. Verify client certificate
            client_cert = load_cert(client_cert_pem)
            if not verify_cert_against_ca(client_cert, self.identity.ca_cert):
                logger.warning("HANDSHAKE: Client cert verification FAILED from %s", self.addr)
                send_raw(self.conn, json.dumps({"error": "invalid_certificate"}).encode())
                return False
            self.client_id = get_cn(client_cert)
            logger.info("HANDSHAKE: Client cert verified for '%s'", self.client_id)

            # 3. Exchange AUTH proofs (sign peer nonce → prove private key)
            server_proof = sign_data(self.identity.private_key, client_nonce)
            auth_msg = {
                "proof": server_proof.hex(),
                "nonce_signed": client_nonce.hex()
            }
            send_raw(self.conn, json.dumps(auth_msg).encode())

            raw = recv_raw(self.conn)
            client_auth = json.loads(raw.decode())
            client_proof = bytes.fromhex(client_auth["proof"])

            if not verify_signature(client_cert.public_key(), server_nonce, client_proof):
                logger.warning("HANDSHAKE: Client proof-of-possession FAILED for '%s'", self.client_id)
                send_raw(self.conn, json.dumps({"error": "auth_failed"}).encode())
                return False
            logger.info("HANDSHAKE: Mutual authentication SUCCESS for '%s'", self.client_id)

            # 4. ECDH key exchange
            server_ecdh_priv, server_ecdh_pub = generate_ec_keypair()
            server_ecdh_pub_pem = server_ecdh_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            send_raw(self.conn, json.dumps({"ecdh_pub": server_ecdh_pub_pem.decode()}).encode())

            raw = recv_raw(self.conn)
            client_ecdh_data = json.loads(raw.decode())
            client_ecdh_pub = load_public_key(client_ecdh_data["ecdh_pub"].encode())

            shared_secret = ecdh_shared_secret(server_ecdh_priv, client_ecdh_pub)
            # server decrypts what client encrypts (c2s), server encrypts with s2c
            self.c2s_key, self.s2c_key = derive_session_keys(shared_secret, client_nonce, server_nonce)

            send_raw(self.conn, json.dumps({"status": "handshake_complete"}).encode())
            logger.info("HANDSHAKE: Session keys established with '%s'", self.client_id)
            return True

        except Exception as e:
            logger.error("HANDSHAKE: Exception for %s: %s", self.addr, e)
            return False

    # ── Request dispatch ────────────────────────────────────────────────────

    def handle(self):
        logger.info("Connection from %s", self.addr)
        if not self.handshake():
            self.conn.close()
            return
        try:
            while True:
                msg = self._recv()
                if not msg:
                    break

                # Replay protection: sequence number must increase
                # (simple; nonce-based replay protection is in upload flow)
                msg_type = msg.get("type")
                payload = msg.get("payload", {})

                if msg_type == "UPLOAD_REQUEST":
                    self._handle_upload(payload)
                elif msg_type == "LIST_FILES":
                    self._handle_list(payload)
                elif msg_type == "DOWNLOAD_REQUEST":
                    self._handle_download(payload)
                elif msg_type == "REVOKE_REQUEST":
                    self._handle_revoke(payload)
                else:
                    self._send("ERROR", {"message": "unknown_message_type"})

        except Exception as e:
            logger.error("Error handling client '%s': %s", self.client_id, e)
        finally:
            self.conn.close()
            logger.info("Connection closed for '%s'", self.client_id)

    # ── Upload ──────────────────────────────────────────────────────────────

    def _handle_upload(self, payload):
        """
        Receive an encrypted file package from sender.
        Verify sender's digital signature before accepting.
        """
        try:
            file_id = payload["file_id"]
            sender_id = payload["sender_id"]
            recipient_id = payload["recipient_id"]
            filename = payload["filename"]
            upload_time = payload["upload_time"]
            expiration = payload["expiration_time"]
            file_hash = payload["file_hash"]
            signature = payload["signature"]
            request_nonce = payload["request_nonce"]
            encrypted_package = payload["encrypted_package"]

            # Replay protection: check request nonce
            if not db_check_nonce(request_nonce):
                logger.warning("UPLOAD: Replay detected from '%s', nonce=%s", sender_id, request_nonce)
                self._send("ERROR", {"message": "replay_detected"})
                return

            # Verify sender is who they claim to be
            if sender_id != self.client_id:
                logger.warning("UPLOAD: sender_id mismatch: claimed '%s', authenticated '%s'",
                               sender_id, self.client_id)
                self._send("ERROR", {"message": "sender_id_mismatch"})
                return

            # Retrieve sender certificate to verify signature
            # (client must send their cert PEM in the payload for verification)
            sender_cert = load_cert(payload["sender_cert"].encode())
            if not verify_cert_against_ca(sender_cert, self.identity.ca_cert):
                logger.warning("UPLOAD: Sender cert invalid for '%s'", sender_id)
                self._send("ERROR", {"message": "invalid_sender_cert"})
                return

            # Verify digital signature over: sender|recipient|file_id|hash|ts|expiry
            sig_payload = build_signature_payload(
                sender_id, recipient_id, file_id, file_hash, upload_time, expiration
            )
            sig_bytes = bytes.fromhex(signature)
            if not verify_signature(sender_cert.public_key(), sig_payload, sig_bytes):
                logger.warning("UPLOAD: Signature verification FAILED for file '%s'", file_id)
                self._send("ERROR", {"message": "invalid_signature"})
                return

            # Verify file hash matches the encrypted ciphertext hash
            ciphertext_bytes = bytes.fromhex(encrypted_package["ciphertext"])
            actual_hash = sha256_hash(ciphertext_bytes)
            if actual_hash != file_hash:
                logger.warning("UPLOAD: File hash mismatch for file '%s'", file_id)
                self._send("ERROR", {"message": "hash_mismatch"})
                return

            # Persist encrypted package to disk
            package_path = os.path.join(STORAGE_DIR, file_id + ".json")
            with open(package_path, "w") as f:
                json.dump(encrypted_package, f)

            # Persist metadata
            db_insert_file({
                "file_id": file_id,
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "filename": filename,
                "upload_time": upload_time,
                "expiration_time": expiration,
                "file_hash": file_hash,
                "signature": signature
            })

            logger.info("UPLOAD: File '%s' stored from '%s' for '%s'",
                        file_id, sender_id, recipient_id)
            self._send("ACK", {"file_id": file_id, "status": "stored"})

        except Exception as e:
            logger.error("UPLOAD: Exception: %s", e)
            self._send("ERROR", {"message": str(e)})

    # ── List ────────────────────────────────────────────────────────────────

    def _handle_list(self, payload):
        """Return list of pending files for the authenticated user."""
        now = time.time()
        files = db_list_pending(self.client_id)
        # Filter expired files
        result = []
        for f in files:
            if f["expiration_time"] < now:
                db_update_status(f["file_id"], "expired")
                logger.info("LIST: File '%s' is expired, marking expired", f["file_id"])
                continue
            result.append({
                "file_id": f["file_id"],
                "sender_id": f["sender_id"],
                "filename": f["filename"],
                "upload_time": f["upload_time"],
                "expiration_time": f["expiration_time"]
            })
        logger.info("LIST: '%s' has %d pending file(s)", self.client_id, len(result))
        self._send("ACK", {"files": result})

    # ── Download ────────────────────────────────────────────────────────────

    def _handle_download(self, payload):
        """Send the encrypted package to the authenticated recipient."""
        file_id = payload["file_id"]
        request_nonce = payload.get("request_nonce", "")

        # Replay protection
        if not db_check_nonce(request_nonce):
            logger.warning("DOWNLOAD: Replay detected for file '%s' by '%s'",
                           file_id, self.client_id)
            self._send("ERROR", {"message": "replay_detected"})
            return

        meta = db_get_file(file_id)
        if not meta:
            logger.warning("DOWNLOAD: File '%s' not found (requested by '%s')",
                           file_id, self.client_id)
            self._send("ERROR", {"message": "file_not_found"})
            return

        # Access control: only intended recipient
        if meta["recipient_id"] != self.client_id:
            logger.warning("DOWNLOAD: UNAUTHORIZED access to '%s' by '%s' (intended: '%s')",
                           file_id, self.client_id, meta["recipient_id"])
            self._send("ERROR", {"message": "access_denied"})
            return

        # Expiration check
        if meta["expiration_time"] < time.time():
            db_update_status(file_id, "expired")
            logger.info("DOWNLOAD: File '%s' is expired. Access denied.", file_id)
            self._send("ERROR", {"message": "file_expired"})
            return

        # Status check
        if meta["status"] != "pending":
            logger.warning("DOWNLOAD: File '%s' status is '%s', not available",
                           file_id, meta["status"])
            self._send("ERROR", {"message": f"file_status_{meta['status']}"})
            return

        # Read encrypted package
        package_path = os.path.join(STORAGE_DIR, file_id + ".json")
        with open(package_path, "r") as f:
            encrypted_package = json.load(f)

        # Mark as downloaded (one-time download bonus feature)
        db_update_status(file_id, "downloaded")
        logger.info("DOWNLOAD: File '%s' sent to '%s'", file_id, self.client_id)

        self._send("ACK", {
            "file_id": file_id,
            "encrypted_package": encrypted_package,
            "signature": meta["signature"],
            "sender_id": meta["sender_id"],
            "file_hash": meta["file_hash"],
            "upload_time": meta["upload_time"],
            "expiration_time": meta["expiration_time"]
        })

    # ── Revoke ──────────────────────────────────────────────────────────────

    def _handle_revoke(self, payload):
        """Sender revokes a pending (not-yet-downloaded) file."""
        file_id = payload["file_id"]
        request_nonce = payload.get("request_nonce", "")

        if not db_check_nonce(request_nonce):
            logger.warning("REVOKE: Replay detected for '%s'", file_id)
            self._send("ERROR", {"message": "replay_detected"})
            return

        meta = db_get_file(file_id)
        if not meta:
            self._send("ERROR", {"message": "file_not_found"})
            return

        if meta["sender_id"] != self.client_id:
            logger.warning("REVOKE: UNAUTHORIZED revoke of '%s' by '%s'",
                           file_id, self.client_id)
            self._send("ERROR", {"message": "access_denied"})
            return

        if meta["status"] != "pending":
            self._send("ERROR", {"message": f"cannot_revoke_status_{meta['status']}"})
            return

        db_update_status(file_id, "revoked")
        # Optionally delete stored file
        package_path = os.path.join(STORAGE_DIR, file_id + ".json")
        if os.path.exists(package_path):
            os.remove(package_path)

        logger.info("REVOKE: File '%s' revoked by sender '%s'", file_id, self.client_id)
        self._send("ACK", {"file_id": file_id, "status": "revoked"})


# ─────────────────────────────────────────────────────────────────────────────
# Main server loop
# ─────────────────────────────────────────────────────────────────────────────

def run_server():
    init_db()
    identity = ServerIdentity()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_HOST, SERVER_PORT))
    server_sock.listen(20)
    logger.info("Server listening on %s:%d", SERVER_HOST, SERVER_PORT)

    while True:
        conn, addr = server_sock.accept()
        handler = ClientHandler(conn, addr, identity)
        t = threading.Thread(target=handler.handle, daemon=True)
        t.start()


if __name__ == "__main__":
    run_server()
