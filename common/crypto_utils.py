"""
Common cryptographic utilities for the Secure Zero-Trust File Drop System.
"""

import os
import json
import struct
import time
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


# ─────────────────────────────────────────────
# Key Generation
# ─────────────────────────────────────────────

def generate_rsa_keypair(key_size=2048):
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()


def generate_ec_keypair():
    """Generate an ECDH/ECDSA key pair (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


# ─────────────────────────────────────────────
# Serialization / Deserialization
# ─────────────────────────────────────────────

def serialize_private_key(private_key, password=None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_data, password=None):
    return serialization.load_pem_private_key(pem_data, password=password)


def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)


def serialize_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert(pem_data):
    return x509.load_pem_x509_certificate(pem_data)


# ─────────────────────────────────────────────
# Certificate Signing Request
# ─────────────────────────────────────────────

def create_csr(private_key, common_name):
    """Create a Certificate Signing Request."""
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, common_name),
           ]))
           .sign(private_key, hashes.SHA256()))
    return csr


def serialize_csr(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr(pem_data):
    return x509.load_pem_x509_csr(pem_data)


# ─────────────────────────────────────────────
# Signatures
# ─────────────────────────────────────────────

def sign_data(private_key, data: bytes) -> bytes:
    """Sign arbitrary bytes with RSA-PSS."""
    return private_key.sign(data, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS signature. Returns True on success."""
    try:
        public_key.verify(signature, data, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
# ECDH Key Exchange
# ─────────────────────────────────────────────

def ecdh_shared_secret(private_key, peer_public_key) -> bytes:
    """Compute ECDH shared secret."""
    return private_key.exchange(ECDH(), peer_public_key)


def derive_session_keys(shared_secret: bytes, nonce_c: bytes, nonce_s: bytes):
    """
    Derive session keys from ECDH shared secret using HKDF-SHA256.
    Returns (client_to_server_key, server_to_client_key) each 32 bytes.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=nonce_c + nonce_s,
        info=b"secure-filedrop-session-v1"
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:32], key_material[32:]


# ─────────────────────────────────────────────
# Symmetric Encryption (AES-GCM)
# ─────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> tuple:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
    """Decrypt AES-256-GCM. Raises on auth failure."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ─────────────────────────────────────────────
# File Encryption (E2E)
# ─────────────────────────────────────────────

def encrypt_file_for_recipient(file_data: bytes, recipient_public_key) -> dict:
    """
    Encrypt file data for a specific recipient.
    1. Generate random 256-bit file key.
    2. Encrypt file with AES-GCM.
    3. Wrap file key with recipient's RSA public key (OAEP).
    Returns a dict with all encrypted components.
    """
    file_key = os.urandom(32)
    nonce, ciphertext = aes_gcm_encrypt(file_key, file_data)

    encrypted_key = recipient_public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "encrypted_key": encrypted_key.hex()
    }


def decrypt_file(encrypted_package: dict, recipient_private_key) -> bytes:
    """
    Decrypt a file package using the recipient's private key.
    """
    file_key = recipient_private_key.decrypt(
        bytes.fromhex(encrypted_package["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce = bytes.fromhex(encrypted_package["nonce"])
    ciphertext = bytes.fromhex(encrypted_package["ciphertext"])
    return aes_gcm_decrypt(file_key, nonce, ciphertext)


# ─────────────────────────────────────────────
# Secure Channel (framing over TCP)
# ─────────────────────────────────────────────

def send_message(sock, encrypt_key: bytes, msg_type: str, payload: dict, seq: int):
    """
    Frame, encrypt, and send a message over a socket.
    Format: [total_len(4)][nonce(12)][ciphertext]
    The plaintext is: JSON({type, seq, timestamp, payload})
    """
    plaintext = json.dumps({
        "type": msg_type,
        "seq": seq,
        "timestamp": time.time(),
        "payload": payload
    }).encode()

    nonce, ciphertext = aes_gcm_encrypt(encrypt_key, plaintext)
    frame = nonce + ciphertext
    header = struct.pack(">I", len(frame))
    sock.sendall(header + frame)


def recv_message(sock, decrypt_key: bytes) -> dict:
    """
    Receive and decrypt a framed message.
    Returns the parsed message dict.
    """
    header = _recv_exact(sock, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    frame = _recv_exact(sock, length)
    nonce = frame[:12]
    ciphertext = frame[12:]
    plaintext = aes_gcm_decrypt(decrypt_key, nonce, ciphertext)
    return json.loads(plaintext.decode())


def send_raw(sock, data: bytes):
    """Send raw bytes with a 4-byte length prefix (used before session key is established)."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_raw(sock) -> bytes:
    """Receive raw bytes with a 4-byte length prefix."""
    header = _recv_exact(sock, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    return _recv_exact(sock, length)


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ─────────────────────────────────────────────
# Hashing / Misc
# ─────────────────────────────────────────────

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_nonce() -> bytes:
    return os.urandom(32)


def generate_file_id() -> str:
    return os.urandom(16).hex()


def build_signature_payload(sender_id: str, recipient_id: str, file_id: str,
                             file_hash: str, timestamp: float, expiration: float) -> bytes:
    """Build the canonical byte string that is signed for a file upload."""
    data = f"{sender_id}|{recipient_id}|{file_id}|{file_hash}|{timestamp}|{expiration}"
    return data.encode()


# ─────────────────────────────────────────────
# Encrypted Note (Bonus 6)
# ─────────────────────────────────────────────

def encrypt_note(note: str, recipient_public_key) -> dict:
    """
    Encrypt a short sender note for the recipient only.
    Uses same AES-GCM + RSA-OAEP scheme as file encryption.
    Returns a dict with nonce, ciphertext, encrypted_key (all hex).
    """
    note_key = os.urandom(32)
    nonce, ciphertext = aes_gcm_encrypt(note_key, note.encode("utf-8"))
    encrypted_key = recipient_public_key.encrypt(
        note_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "encrypted_key": encrypted_key.hex()
    }


def decrypt_note(encrypted_note: dict, recipient_private_key) -> str:
    """Decrypt an encrypted note using the recipient's private key."""
    note_key = recipient_private_key.decrypt(
        bytes.fromhex(encrypted_note["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce = bytes.fromhex(encrypted_note["nonce"])
    ciphertext = bytes.fromhex(encrypted_note["ciphertext"])
    return aes_gcm_decrypt(note_key, nonce, ciphertext).decode("utf-8")


# ─────────────────────────────────────────────
# Confidential Metadata (Bonus 3)
# ─────────────────────────────────────────────

def encrypt_metadata(metadata: dict, recipient_public_key) -> dict:
    """
    Encrypt non-routing metadata (e.g. filename, description) for the recipient.
    Fields that must stay visible for routing (recipient_id, file_id, status)
    are NOT included here — only sensitive optional fields.
    Returns encrypted blob dict.
    """
    plaintext = json.dumps(metadata).encode("utf-8")
    meta_key = os.urandom(32)
    nonce, ciphertext = aes_gcm_encrypt(meta_key, plaintext)
    encrypted_key = recipient_public_key.encrypt(
        meta_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "encrypted_key": encrypted_key.hex()
    }


def decrypt_metadata(encrypted_meta: dict, recipient_private_key) -> dict:
    """Decrypt confidential metadata blob using recipient's private key."""
    meta_key = recipient_private_key.decrypt(
        bytes.fromhex(encrypted_meta["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce = bytes.fromhex(encrypted_meta["nonce"])
    ciphertext = bytes.fromhex(encrypted_meta["ciphertext"])
    plaintext = aes_gcm_decrypt(meta_key, nonce, ciphertext)
    return json.loads(plaintext.decode("utf-8"))


# ─────────────────────────────────────────────
# Large File Chunking (Bonus 4)
# ─────────────────────────────────────────────

CHUNK_SIZE = 64 * 1024  # 64 KB per chunk


def split_into_chunks(file_data: bytes, chunk_size: int = CHUNK_SIZE) -> list:
    """
    Split file_data into fixed-size chunks.
    Returns list of dicts: {chunk_index, total_chunks, data (bytes), chunk_hash}.
    """
    chunks = []
    total = (len(file_data) + chunk_size - 1) // chunk_size
    for i in range(total):
        chunk_data = file_data[i * chunk_size: (i + 1) * chunk_size]
        chunks.append({
            "chunk_index": i,
            "total_chunks": total,
            "data": chunk_data,
            "chunk_hash": hashlib.sha256(chunk_data).hexdigest()
        })
    return chunks


def encrypt_chunks(file_data: bytes, recipient_public_key) -> dict:
    """
    Encrypt file as ordered chunks. Each chunk is individually AES-GCM encrypted
    with the same file key. The file key is RSA-OAEP wrapped for the recipient.
    Returns a dict suitable for JSON serialisation.
    """
    file_key = os.urandom(32)
    chunks = split_into_chunks(file_data)
    encrypted_chunks = []
    for ch in chunks:
        nonce, ciphertext = aes_gcm_encrypt(file_key, ch["data"])
        encrypted_chunks.append({
            "chunk_index": ch["chunk_index"],
            "total_chunks": ch["total_chunks"],
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "chunk_hash": ch["chunk_hash"]   # hash of plaintext chunk for integrity
        })

    encrypted_key = recipient_public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Also store a hash of all chunk hashes in order (manifest hash)
    manifest = "|".join(c["chunk_hash"] for c in encrypted_chunks)
    manifest_hash = hashlib.sha256(manifest.encode()).hexdigest()

    return {
        "chunked": True,
        "total_chunks": len(chunks),
        "manifest_hash": manifest_hash,
        "encrypted_key": encrypted_key.hex(),
        "chunks": encrypted_chunks
    }


def decrypt_chunks(chunked_package: dict, recipient_private_key) -> bytes:
    """
    Decrypt a chunked file package.
    Verifies chunk ordering, per-chunk hashes, and manifest hash.
    Raises ValueError on integrity failure.
    """
    file_key = recipient_private_key.decrypt(
        bytes.fromhex(chunked_package["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    chunks = chunked_package["chunks"]
    total = chunked_package["total_chunks"]

    # Sort by chunk_index to handle any reordering
    chunks_sorted = sorted(chunks, key=lambda c: c["chunk_index"])

    # Detect missing or duplicated chunks
    indices = [c["chunk_index"] for c in chunks_sorted]
    if indices != list(range(total)):
        raise ValueError(f"Chunk sequence error: expected 0..{total-1}, got {indices}")

    # Verify manifest hash
    manifest = "|".join(c["chunk_hash"] for c in chunks_sorted)
    if hashlib.sha256(manifest.encode()).hexdigest() != chunked_package["manifest_hash"]:
        raise ValueError("Manifest hash mismatch — chunks may be modified or reordered.")

    reassembled = b""
    for ch in chunks_sorted:
        nonce = bytes.fromhex(ch["nonce"])
        ciphertext = bytes.fromhex(ch["ciphertext"])
        plaintext = aes_gcm_decrypt(file_key, nonce, ciphertext)
        # Verify per-chunk plaintext hash
        if hashlib.sha256(plaintext).hexdigest() != ch["chunk_hash"]:
            raise ValueError(f"Chunk {ch['chunk_index']} integrity check failed.")
        reassembled += plaintext

    return reassembled


# ─────────────────────────────────────────────
# Recipient Acknowledgement (Bonus 5)
# ─────────────────────────────────────────────

def build_ack_payload(recipient_id: str, file_id: str, timestamp: float) -> bytes:
    """Build the canonical bytes for a recipient acknowledgement signature."""
    data = f"ACK|{recipient_id}|{file_id}|{timestamp}"
    return data.encode()


def sign_recipient_ack(private_key, file_id: str, recipient_id: str) -> dict:
    """
    Generate a signed acknowledgement after successful download+verification.
    Returns a dict with ack_timestamp, recipient_id, file_id, signature (hex).
    """
    ack_ts = time.time()
    payload = build_ack_payload(recipient_id, file_id, ack_ts)
    signature = sign_data(private_key, payload)
    return {
        "recipient_id": recipient_id,
        "file_id": file_id,
        "ack_timestamp": ack_ts,
        "signature": signature.hex()
    }


def verify_recipient_ack(ack: dict, recipient_public_key) -> bool:
    """Verify a recipient acknowledgement signature. Returns True on success."""
    try:
        payload = build_ack_payload(
            ack["recipient_id"], ack["file_id"], ack["ack_timestamp"]
        )
        sig = bytes.fromhex(ack["signature"])
        return verify_signature(recipient_public_key, payload, sig)
    except Exception:
        return False
