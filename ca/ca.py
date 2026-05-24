"""
Certificate Authority (CA) for the Secure Zero-Trust File Drop System.

The CA:
  - Generates its own RSA key pair and self-signed certificate on first run.
  - Listens on a TCP port for certificate signing requests (CSRs).
  - Issues signed certificates to clients and the server.
  - Saves its state (key + cert) to disk for persistence.

Protocol (plaintext, pre-trust phase):
  Client → CA : RAW( JSON({ "csr": <PEM>, "identity": <str> }) )
  CA → Client : RAW( JSON({ "certificate": <PEM>, "ca_cert": <PEM> }) )
"""

import os
import sys
import json
import socket
import threading
import datetime

# Allow imports from parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

from common.crypto_utils import (
    generate_rsa_keypair, serialize_private_key, serialize_public_key,
    load_private_key, serialize_cert, load_cert, load_csr,
    send_raw, recv_raw
)
from common.logger import get_logger

CA_HOST = "127.0.0.1"
CA_PORT = 9000
CA_KEY_FILE = os.path.join(os.path.dirname(__file__), "ca_private_key.pem")
CA_CERT_FILE = os.path.join(os.path.dirname(__file__), "ca_cert.pem")
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")

logger = get_logger("CA", LOG_DIR)


class CertificateAuthority:
    def __init__(self):
        self.private_key, self.public_key = self._load_or_create_ca_keys()
        self.certificate = self._load_or_create_ca_cert()
        logger.info("CA initialized. Subject: %s", self.certificate.subject.rfc4514_string())

    # ── Key / Cert persistence ──────────────────────────────────────────────

    def _load_or_create_ca_keys(self):
        if os.path.exists(CA_KEY_FILE):
            logger.info("Loading existing CA private key from %s", CA_KEY_FILE)
            with open(CA_KEY_FILE, "rb") as f:
                private_key = load_private_key(f.read())
            return private_key, private_key.public_key()

        logger.info("Generating new CA RSA-2048 key pair …")
        private_key, public_key = generate_rsa_keypair(2048)
        with open(CA_KEY_FILE, "wb") as f:
            f.write(serialize_private_key(private_key))
        logger.info("CA private key saved to %s", CA_KEY_FILE)
        return private_key, public_key

    def _load_or_create_ca_cert(self):
        if os.path.exists(CA_CERT_FILE):
            logger.info("Loading existing CA certificate from %s", CA_CERT_FILE)
            with open(CA_CERT_FILE, "rb") as f:
                return load_cert(f.read())

        logger.info("Creating self-signed CA certificate …")
        cert = self._build_self_signed_cert()
        with open(CA_CERT_FILE, "wb") as f:
            f.write(serialize_cert(cert))
        logger.info("CA certificate saved to %s", CA_CERT_FILE)
        return cert

    def _build_self_signed_cert(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureFileDrop-CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureFileDrop"),
        ])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(self.public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(self.private_key, hashes.SHA256()))
        return cert

    # ── Certificate Issuance ────────────────────────────────────────────────

    def issue_certificate(self, csr_pem: bytes, identity: str):
        """Sign a CSR and return the issued certificate."""
        csr = load_csr(csr_pem)

        # Validate CSR signature
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR signature")

        now = datetime.datetime.utcnow()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, identity),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureFileDrop"),
        ])
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self.certificate.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(self.private_key, hashes.SHA256()))

        logger.info("Issued certificate for identity '%s'", identity)
        return cert

    # ── Verification Helper ─────────────────────────────────────────────────

    def verify_certificate(self, cert_pem: bytes) -> bool:
        """Verify that a certificate was issued by this CA."""
        try:
            cert = load_cert(cert_pem)
            ca_pub = self.certificate.public_key()
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                __import__('cryptography').hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            now = datetime.datetime.utcnow()
            if not (cert.not_valid_before_utc.replace(tzinfo=None) <= now <= cert.not_valid_after_utc.replace(tzinfo=None)):
                logger.warning("Certificate validity period check failed")
                return False
            return True
        except Exception as e:
            logger.warning("Certificate verification failed: %s", e)
            return False

    # ── TCP Server ──────────────────────────────────────────────────────────

    def handle_client(self, conn, addr):
        logger.info("CSR request from %s", addr)
        try:
            raw = recv_raw(conn)
            if not raw:
                return
            request = json.loads(raw.decode())
            csr_pem = request["csr"].encode()
            identity = request["identity"]

            cert = self.issue_certificate(csr_pem, identity)
            response = {
                "certificate": serialize_cert(cert).decode(),
                "ca_cert": serialize_cert(self.certificate).decode()
            }
            send_raw(conn, json.dumps(response).encode())
            logger.info("Certificate sent to %s for identity '%s'", addr, identity)
        except Exception as e:
            logger.error("Error handling CSR from %s: %s", addr, e)
            send_raw(conn, json.dumps({"error": str(e)}).encode())
        finally:
            conn.close()

    def run(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((CA_HOST, CA_PORT))
        server_sock.listen(10)
        logger.info("CA listening on %s:%d", CA_HOST, CA_PORT)
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
            t.start()


def request_certificate(identity: str, csr_pem: bytes):
    """
    Helper used by clients/server to request a certificate from the CA.
    Returns (cert_pem, ca_cert_pem).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((CA_HOST, CA_PORT))
    request = {"csr": csr_pem.decode(), "identity": identity}
    send_raw(sock, json.dumps(request).encode())
    raw = recv_raw(sock)
    sock.close()
    response = json.loads(raw.decode())
    if "error" in response:
        raise RuntimeError(f"CA error: {response['error']}")
    return response["certificate"].encode(), response["ca_cert"].encode()


if __name__ == "__main__":
    ca = CertificateAuthority()
    ca.run()
