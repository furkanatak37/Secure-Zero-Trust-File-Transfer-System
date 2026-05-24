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
