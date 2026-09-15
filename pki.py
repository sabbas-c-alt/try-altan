"""
pki.py — Shared PKI utilities for the EBW prototype.

Requires: pip install cryptography
"""

from __future__ import annotations

import ipaddress
import os
import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BOOTSTRAP_CA_CERT_FILE = os.environ.get("BOOTSTRAP_CA_CERT_FILE", "bootstrap_ca_cert.pem")
BOOTSTRAP_CA_KEY_FILE  = os.environ.get("BOOTSTRAP_CA_KEY_FILE",  "bootstrap_ca_key.pem")
OP_CA_CERT_FILE        = os.environ.get("OP_CA_CERT_FILE",        "op_ca_cert.pem")
OP_CA_KEY_FILE         = os.environ.get("OP_CA_KEY_FILE",         "op_ca_key.pem")

BOOTSTRAP_VALIDITY_DAYS = 365 * 30
SVC_CERT_VALIDITY_DAYS = 365

_SAN_NAMES = [
    x509.DNSName("localhost"),
    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
]


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def key_to_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def pem_to_key(pem: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem.encode(), password=None)


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------

def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def pem_to_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


# ---------------------------------------------------------------------------
# CSR helpers
# ---------------------------------------------------------------------------

def make_csr(key: rsa.RSAPrivateKey, subject: str) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .sign(key, hashes.SHA256())
    )


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def pem_to_csr(pem: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(pem.encode())


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _build_cert(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    not_after: datetime,
    extra_extensions=(),
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    )
    for ext in extra_extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def sign_csr(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    validity_days: int,
) -> x509.Certificate:
    not_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
    return _build_cert(csr, ca_cert, ca_key, not_after)


def sign_csr_seconds(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    validity_seconds: int,
) -> x509.Certificate:
    not_after = datetime.now(timezone.utc) + timedelta(seconds=validity_seconds)
    return _build_cert(csr, ca_cert, ca_key, not_after)


# ---------------------------------------------------------------------------
# CA cert (self-signed) and server cert (with SAN)
# ---------------------------------------------------------------------------

def make_ca_cert(key: rsa.RSAPrivateKey, cn: str = "EBW-IdentityCA") -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=BOOTSTRAP_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_SAN_NAMES), critical=False)
        .sign(key, hashes.SHA256())
    )


def sign_server_csr(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    validity_days: int,
) -> x509.Certificate:
    san_ext = x509.SubjectAlternativeName(_SAN_NAMES)
    not_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
    return _build_cert(csr, ca_cert, ca_key, not_after, extra_extensions=[san_ext])


# ---------------------------------------------------------------------------
# Cert validation
# ---------------------------------------------------------------------------

def cert_signed_by_ca(cert_pem: str, ca_cert_pem: str) -> bool:
    """Return True if cert was signed by the given CA."""
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.exceptions import InvalidSignature
    cert = pem_to_cert(cert_pem)
    ca_cert = pem_to_cert(ca_cert_pem)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            _padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Cert lifetime query
# ---------------------------------------------------------------------------

def cert_seconds_remaining(cert_pem: str) -> float:
    cert = pem_to_cert(cert_pem)
    delta = cert.not_valid_after_utc - datetime.now(timezone.utc)
    return delta.total_seconds()


# ---------------------------------------------------------------------------
# SSL contexts
# ---------------------------------------------------------------------------

def server_ssl_context(
    cert_file: str,
    key_file: str,
    ca_cert_file: str | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    if ca_cert_file:
        ctx.load_verify_locations(ca_cert_file)
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def client_ssl_context(
    ca_cert_file: str,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_cert_file)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cert_file and key_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx
