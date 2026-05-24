"""
Secure File Drop — Client

Operations:
  register  - Obtain a CA-signed certificate for this user.
  upload    - Encrypt and upload a file to a recipient.
  list      - List pending files addressed to this user.
  download  - Download and decrypt a file.
  revoke    - Revoke a previously uploaded (not yet downloaded) file.

Usage:
  python client.py register <username>
  python client.py upload   <username> <recipient> <filepath> [--expires <hours>]
  python client.py list     <username>
  python client.py download <username> <file_id>
  python client.py revoke   <username> <file_id>
"""

import os
import sys
import json
import socket
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

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
    encrypt_file_for_recipient, decrypt_file,
    send_message, recv_message, send_raw, recv_raw
)
from common.logger import get_logger
from ca.ca import request_certificate

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001
CLIENT_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(CLIENT_DIR, "logs")
DOWNLOAD_DIR = os.path.join(CLIENT_DIR, "downloads")

os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def client_dir(username):
    d = os.path.join(CLIENT_DIR, "identities", username)
    os.makedirs(d, exist_ok=True)
    return d


def key_file(username):
    return os.path.join(client_dir(username), "private_key.pem")


def cert_file(username):
    return os.path.join(client_dir(username), "cert.pem")


def ca_cert_file(username):
    return os.path.join(client_dir(username), "ca_cert.pem")


def pub_key_file(username):
    return os.path.join(client_dir(username), "public_key.pem")


# ─────────────────────────────────────────────────────────────────────────────
# Identity helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_identity(username):
    """Load private key, certificate, CA cert for a registered user."""
    try:
        with open(key_file(username), "rb") as f:
            private_key = load_private_key(f.read())
        with open(cert_file(username), "rb") as f:
            cert = load_cert(f.read())
        with open(ca_cert_file(username), "rb") as f:
            ca_cert = load_cert(f.read())
        return private_key, cert, ca_cert
    except FileNotFoundError:
        print(f"[ERROR] User '{username}' not registered. Run 'register' first.")
        sys.exit(1)


def load_recipient_pub_key(recipient):
    """Load a recipient's public key (must have been registered)."""
    path = pub_key_file(recipient)
    if not os.path.exists(path):
        # Try to find the cert and extract public key
        c_file = cert_file(recipient)
        if os.path.exists(c_file):
            with open(c_file, "rb") as f:
                cert = load_cert(f.read())
            return cert.public_key()
        print(f"[ERROR] Cannot find public key for recipient '{recipient}'.")
        print(f"        Make sure they have registered and their cert is at {c_file}")
        sys.exit(1)
    with open(path, "rb") as f:
        return load_public_key(f.read())


# ─────────────────────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────────────────────

def cmd_register(username):
    logger = get_logger(f"CLIENT-{username}", LOG_DIR)

    if os.path.exists(cert_file(username)):
        print(f"[INFO] '{username}' is already registered.")
        return

    logger.info("Generating RSA-2048 key pair for '%s' …", username)
    private_key, public_key = generate_rsa_keypair(2048)

    csr = create_csr(private_key, username)
    cert_pem, ca_cert_pem = request_certificate(username, serialize_csr(csr))

    with open(key_file(username), "wb") as f:
        f.write(serialize_private_key(private_key))
    with open(cert_file(username), "wb") as f:
        f.write(cert_pem)
    with open(ca_cert_file(username), "wb") as f:
        f.write(ca_cert_pem)
    with open(pub_key_file(username), "wb") as f:
        f.write(serialize_public_key(public_key))

    logger.info("Registration complete for '%s'.", username)
    print(f"[OK] '{username}' registered successfully.")


# ─────────────────────────────────────────────────────────────────────────────
# Secure session
# ─────────────────────────────────────────────────────────────────────────────

class SecureSession:
    """
    Establishes a mutually authenticated session with the server.
    After construction, use send() / recv() for encrypted comms.
    """

    def __init__(self, username):
        self.username = username
        self.logger = get_logger(f"CLIENT-{username}", LOG_DIR)
        self.private_key, self.cert, self.ca_cert = load_identity(username)
        self.sock = None
        self.c2s_key = None  # client encrypts with this
        self.s2c_key = None  # client decrypts with this
        self.seq = 0

    def _next_seq(self):
        self.seq += 1
        return self.seq

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        self._handshake()

    def _verify_cert_against_ca(self, cert):
        import datetime
        from cryptography.hazmat.primitives.asymmetric import padding
        try:
            ca_pub = self.ca_cert.public_key()
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

    def _handshake(self):
        # 1. Receive server HELLO
        raw = recv_raw(self.sock)
        server_hello = json.loads(raw.decode())
        server_cert = load_cert(server_hello["cert"].encode())
        server_nonce = bytes.fromhex(server_hello["nonce"])

        # Verify server certificate
        if not self._verify_cert_against_ca(server_cert):
            raise RuntimeError("Server certificate verification FAILED — aborting.")
        self.logger.info("HANDSHAKE: Server cert verified.")

        # Send client HELLO
        client_nonce = generate_nonce()
        client_hello = {
            "cert": serialize_cert(self.cert).decode(),
            "nonce": client_nonce.hex()
        }
        send_raw(self.sock, json.dumps(client_hello).encode())

        # 2. Receive server AUTH proof
        raw = recv_raw(self.sock)
        server_auth = json.loads(raw.decode())
        server_proof = bytes.fromhex(server_auth["proof"])
        if not verify_signature(server_cert.public_key(), client_nonce, server_proof):
            raise RuntimeError("Server proof-of-possession FAILED — possible MITM.")
        self.logger.info("HANDSHAKE: Server authenticated.")

        # Send client AUTH proof
        client_proof = sign_data(self.private_key, server_nonce)
        send_raw(self.sock, json.dumps({"proof": client_proof.hex()}).encode())

        # 3. ECDH key exchange
        ecdh_priv, ecdh_pub = generate_ec_keypair()
        ecdh_pub_pem = ecdh_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Receive server ECDH pub
        raw = recv_raw(self.sock)
        server_ecdh_data = json.loads(raw.decode())
        server_ecdh_pub = load_public_key(server_ecdh_data["ecdh_pub"].encode())

        # Send client ECDH pub
        send_raw(self.sock, json.dumps({"ecdh_pub": ecdh_pub_pem.decode()}).encode())

        shared_secret = ecdh_shared_secret(ecdh_priv, server_ecdh_pub)
        self.c2s_key, self.s2c_key = derive_session_keys(shared_secret, client_nonce, server_nonce)

        # Wait for handshake_complete
        raw = recv_raw(self.sock)
        status = json.loads(raw.decode())
        if status.get("status") != "handshake_complete":
            raise RuntimeError("Handshake did not complete properly.")
        self.logger.info("HANDSHAKE: Session established with server.")

    def send(self, msg_type, payload):
        send_message(self.sock, self.c2s_key, msg_type, payload, self._next_seq())

    def recv(self):
        return recv_message(self.sock, self.s2c_key)

    def close(self):
        if self.sock:
            self.sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Upload
# ─────────────────────────────────────────────────────────────────────────────

def cmd_upload(username, recipient, filepath, expires_hours=24):
    logger = get_logger(f"CLIENT-{username}", LOG_DIR)

    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    # Load recipient public key
    recipient_pub_key = load_recipient_pub_key(recipient)

    with open(filepath, "rb") as f:
        file_data = f.read()

    filename = os.path.basename(filepath)
    file_id = generate_file_id()
    upload_time = time.time()
    expiration_time = upload_time + expires_hours * 3600
    request_nonce = generate_nonce().hex()

    # Encrypt file for recipient
    encrypted_package = encrypt_file_for_recipient(file_data, recipient_pub_key)
    file_hash = sha256_hash(bytes.fromhex(encrypted_package["ciphertext"]))

    # Sign the file metadata
    private_key, cert, _ = load_identity(username)
    sig_payload = build_signature_payload(
        username, recipient, file_id, file_hash, upload_time, expiration_time
    )
    signature = sign_data(private_key, sig_payload).hex()

    session = SecureSession(username)
    session.connect()

    payload = {
        "file_id": file_id,
        "sender_id": username,
        "recipient_id": recipient,
        "filename": filename,
        "upload_time": upload_time,
        "expiration_time": expiration_time,
        "file_hash": file_hash,
        "signature": signature,
        "request_nonce": request_nonce,
        "encrypted_package": encrypted_package,
        "sender_cert": serialize_cert(cert).decode()
    }

    session.send("UPLOAD_REQUEST", payload)
    response = session.recv()
    session.close()

    if response and response.get("type") == "ACK":
        print(f"[OK] File uploaded. file_id = {file_id}")
        logger.info("Upload success: file_id=%s recipient=%s", file_id, recipient)
    else:
        err = response.get("payload", {}).get("message", "unknown") if response else "no response"
        print(f"[ERROR] Upload failed: {err}")
        logger.error("Upload failed: %s", err)


# ─────────────────────────────────────────────────────────────────────────────
# List
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list(username):
    logger = get_logger(f"CLIENT-{username}", LOG_DIR)
    session = SecureSession(username)
    session.connect()
    session.send("LIST_FILES", {})
    response = session.recv()
    session.close()

    if response and response.get("type") == "ACK":
        files = response["payload"].get("files", [])
        if not files:
            print("No pending files.")
        else:
            print(f"{'File ID':<34} {'From':<15} {'Filename':<25} {'Expires'}")
            print("-" * 90)
            for f in files:
                exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(f["expiration_time"]))
                print(f"{f['file_id']:<34} {f['sender_id']:<15} {f['filename']:<25} {exp}")
        logger.info("Listed %d pending file(s)", len(files))
    else:
        err = response.get("payload", {}).get("message", "?") if response else "no response"
        print(f"[ERROR] {err}")


# ─────────────────────────────────────────────────────────────────────────────
# Download
# ─────────────────────────────────────────────────────────────────────────────

def cmd_download(username, file_id):
    logger = get_logger(f"CLIENT-{username}", LOG_DIR)
    private_key, cert, ca_cert = load_identity(username)
    request_nonce = generate_nonce().hex()

    session = SecureSession(username)
    session.connect()
    session.send("DOWNLOAD_REQUEST", {"file_id": file_id, "request_nonce": request_nonce})
    response = session.recv()
    session.close()

    if not response or response.get("type") != "ACK":
        err = response.get("payload", {}).get("message", "?") if response else "no response"
        print(f"[ERROR] Download failed: {err}")
        logger.error("Download failed for file_id=%s: %s", file_id, err)
        return

    payload = response["payload"]
    encrypted_package = payload["encrypted_package"]
    signature_hex = payload["signature"]
    sender_id = payload["sender_id"]
    file_hash = payload["file_hash"]
    expiration = payload["expiration_time"]

    # Decrypt the file
    try:
        file_data = decrypt_file(encrypted_package, private_key)
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        logger.error("Decryption failed for file_id=%s: %s", file_id, e)
        return

    # Verify integrity: hash of ciphertext
    actual_hash = sha256_hash(bytes.fromhex(encrypted_package["ciphertext"]))
    if actual_hash != file_hash:
        print("[ERROR] File hash mismatch — file may be tampered!")
        logger.error("Hash mismatch on download for file_id=%s", file_id)
        return

    # Verify sender signature
    upload_time = payload.get("upload_time")
    sig_payload = build_signature_payload(
        sender_id, username, file_id, file_hash,
        upload_time, expiration
    )
    # Load sender cert to verify signature
    sender_cert_path = cert_file(sender_id)
    if not os.path.exists(sender_cert_path):
        print(f"[WARN] Cannot find sender '{sender_id}' certificate for signature verification.")
        logger.warning("Sender cert not found for '%s'", sender_id)
    else:
        with open(sender_cert_path, "rb") as f:
            sender_cert = load_cert(f.read())
        sig_bytes = bytes.fromhex(signature_hex)
        if not verify_signature(sender_cert.public_key(), sig_payload, sig_bytes):
            print("[ERROR] Sender signature verification FAILED — rejecting file!")
            logger.error("Signature verification FAILED for file_id=%s from '%s'",
                         file_id, sender_id)
            return
        print(f"[OK] Signature verified — file is from '{sender_id}'.")
        logger.info("Signature verified for file_id=%s from '%s'", file_id, sender_id)

    # Save decrypted file
    out_path = os.path.join(DOWNLOAD_DIR, file_id + "_decrypted")
    with open(out_path, "wb") as f:
        f.write(file_data)

    print(f"[OK] File downloaded and decrypted → {out_path}")
    logger.info("File '%s' downloaded successfully by '%s'", file_id, username)


# ─────────────────────────────────────────────────────────────────────────────
# Revoke
# ─────────────────────────────────────────────────────────────────────────────

def cmd_revoke(username, file_id):
    logger = get_logger(f"CLIENT-{username}", LOG_DIR)
    request_nonce = generate_nonce().hex()

    session = SecureSession(username)
    session.connect()
    session.send("REVOKE_REQUEST", {"file_id": file_id, "request_nonce": request_nonce})
    response = session.recv()
    session.close()

    if response and response.get("type") == "ACK":
        print(f"[OK] File '{file_id}' has been revoked.")
        logger.info("File '%s' revoked by '%s'", file_id, username)
    else:
        err = response.get("payload", {}).get("message", "?") if response else "no response"
        print(f"[ERROR] Revoke failed: {err}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Secure Zero-Trust File Drop Client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # register
    p = subparsers.add_parser("register", help="Register a new user")
    p.add_argument("username")

    # upload
    p = subparsers.add_parser("upload", help="Upload a file for a recipient")
    p.add_argument("username")
    p.add_argument("recipient")
    p.add_argument("filepath")
    p.add_argument("--expires", type=float, default=24, help="Expiration in hours (default 24)")

    # list
    p = subparsers.add_parser("list", help="List pending files")
    p.add_argument("username")

    # download
    p = subparsers.add_parser("download", help="Download and decrypt a file")
    p.add_argument("username")
    p.add_argument("file_id")

    # revoke
    p = subparsers.add_parser("revoke", help="Revoke an uploaded file (before download)")
    p.add_argument("username")
    p.add_argument("file_id")

    args = parser.parse_args()

    if args.command == "register":
        cmd_register(args.username)
    elif args.command == "upload":
        cmd_upload(args.username, args.recipient, args.filepath, args.expires)
    elif args.command == "list":
        cmd_list(args.username)
    elif args.command == "download":
        cmd_download(args.username, args.file_id)
    elif args.command == "revoke":
        cmd_revoke(args.username, args.file_id)


if __name__ == "__main__":
    main()
