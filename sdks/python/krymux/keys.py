"""Ed25519 identities: keypair generation, self-signed certificates, and the
canonical SPKI-sha256 fingerprint used for whitelisting and pinning.

The canonical identity of a peer is ``sha256:<hex>(sha256(SPKI DER))`` —
byte-identical to the Rust and Node reference implementations, so whitelists
and pins transfer 1:1 between implementations.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

PathLike = Union[str, Path]

#: DER SubjectPublicKeyInfo prefix for Ed25519 (RFC 8410) + 32-byte raw key.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

_CERT_VALID_FROM = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
_CERT_VALID_TO = datetime.datetime(2049, 12, 31, tzinfo=datetime.timezone.utc)

_FP_RE = re.compile(r"^[0-9a-f]{64}$")


def spki_from_ed25519_raw(raw: bytes) -> bytes:
    """Build the DER SubjectPublicKeyInfo for a raw 32-byte Ed25519 key."""
    return ED25519_SPKI_PREFIX + raw


def fingerprint_of_spki(spki: bytes) -> str:
    """Canonical ``sha256:<hex>`` fingerprint of an SPKI DER blob."""
    return "sha256:" + hashlib.sha256(spki).hexdigest()


def _spki_der(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint_of_cert(cert: x509.Certificate) -> str:
    """Canonical fingerprint of a certificate (sha256 over its SPKI DER)."""
    return fingerprint_of_spki(_spki_der(cert))


def fingerprint_of_cert_der(cert_der: bytes) -> str:
    """Canonical fingerprint of a DER-encoded certificate."""
    return fingerprint_of_cert(x509.load_der_x509_certificate(cert_der))


@dataclass
class Identity:
    """An Ed25519 identity: key pair, self-signed certificate, fingerprint."""

    key: ed25519.Ed25519PrivateKey
    cert: x509.Certificate
    fingerprint: str
    #: Source paths when loaded from disk (None when generated in memory).
    key_path: Path | None = None
    cert_path: Path | None = None
    _ssl_dir: Path | None = None

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def ssl_pair(self) -> tuple[Path, Path]:
        """(cert_path, key_path) usable with ``ssl.SSLContext.load_cert_chain``.

        Always materializes the identity's own canonical PEM pair (clean
        PKCS#8 v1 key): source files written by the Rust CLI carry CRLF line
        endings and a PKCS#8 v2 layout that some OpenSSL PEM readers reject,
        so re-serialized copies are the portable form. Files are written once
        per Identity; call :meth:`cleanup` to remove them.
        """
        if self._ssl_dir is None:
            import tempfile

            self._ssl_dir = Path(tempfile.mkdtemp(prefix="krymux-identity-"))
            (self._ssl_dir / "identity.crt.pem").write_bytes(self.cert_pem)
            (self._ssl_dir / "identity.key.pem").write_bytes(self.key_pem)
        return self._ssl_dir / "identity.crt.pem", self._ssl_dir / "identity.key.pem"

    def cleanup(self) -> None:
        """Remove PEM files materialized by :meth:`ssl_pair` (if any)."""
        import shutil

        if self._ssl_dir is not None:
            shutil.rmtree(self._ssl_dir, ignore_errors=True)
            self._ssl_dir = None


def generate_identity(cn: str = "krymux") -> Identity:
    """Generate a fresh Ed25519 identity with a self-signed X.509 certificate.

    Mirrors the Rust reference: CN ``"<cn> <16 hex of fingerprint>"``, SAN
    ``krymux``, validity 2025-01-01 .. 2049-12-31.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = fingerprint_of_spki(spki)
    short = fingerprint[len("sha256:") : len("sha256:") + 16]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cn} {short}")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_CERT_VALID_FROM)
        .not_valid_after(_CERT_VALID_TO)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("krymux")]), critical=False
        )
        .sign(key, algorithm=None)  # Ed25519: algorithm must be None
    )
    return Identity(key=key, cert=cert, fingerprint=fingerprint)


def _read_pem(data: bytes) -> bytes:
    """Normalize PEM bytes: the Rust CLI writes CRLF line endings, which
    OpenSSL tolerates but the cryptography parser does not."""
    return data.replace(b"\r\n", b"\n")


def _pem_body(data: bytes) -> bytes:
    import base64

    lines = [l for l in data.splitlines() if l and not l.startswith(b"-----")]
    return base64.b64decode(b"".join(lines))


def _der_children(buf: bytes) -> list[bytes]:
    """Split DER buffer into top-level TLV elements (bytes, each incl. tag)."""
    out: list[bytes] = []
    off = 0
    while off + 2 <= len(buf):
        length = buf[off + 1]
        header = 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4 or off + 2 + n > len(buf):
                break
            length = int.from_bytes(buf[off + 2 : off + 2 + n], "big")
            header = 2 + n
        if off + header + length > len(buf):
            break
        out.append(buf[off : off + header + length])
        off += header + length
    return out


def _tlv_parts(elem: bytes) -> tuple[int, bytes]:
    """(tag, content) of one DER TLV element produced by ``_der_children``."""
    tag = elem[0]
    length = elem[1]
    header = 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(elem[2 : 2 + n], "big")
        header = 2 + n
    return tag, elem[header : header + length]


def _ed25519_from_pkcs8(pem: bytes) -> ed25519.Ed25519PrivateKey:
    """Tolerant PKCS#8 reader for Ed25519 keys.

    The Rust CLI (rcgen) emits PKCS#8 v2 (``version 1`` plus a ``[1]``
    public-key attribute); OpenSSL accepts it but the cryptography PKCS#8
    parser does not. Extract the 32-byte seed and rebuild the key directly.
    """
    der = _pem_body(pem)
    top = _der_children(der)
    if not top or top[0][0] != 0x30:
        raise ValueError("not a PKCS#8 private key")
    children = _der_children(_tlv_parts(top[0])[1])
    # children: [0] version INTEGER, [1] algorithm SEQUENCE, [2] privateKey OCTET STRING
    if len(children) < 3 or children[0][0] != 0x02 or children[2][0] != 0x04:
        raise ValueError("not a PKCS#8 private key")
    tag, alg = _tlv_parts(children[1])
    if b"\x06\x03\x2b\x65\x70" not in alg:  # OID 1.3.101.112 (Ed25519)
        raise ValueError("PKCS#8 key is not Ed25519")
    inner = _tlv_parts(children[2])[1]  # content of the outer OCTET STRING
    seed = inner[-32:]  # inner OCTET STRING (or raw) holding the 32-byte seed
    if len(seed) != 32:
        raise ValueError("cannot extract 32-byte Ed25519 seed")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def load_identity(key_path: PathLike, cert_path: PathLike) -> Identity:
    """Load a key/certificate PEM pair and derive its fingerprint.

    Compatible with PEM files produced by ``krymux-tunnel keygen``.
    """
    key_path = Path(key_path)
    cert_path = Path(cert_path)
    key_pem = _read_pem(key_path.read_bytes())
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except ValueError:
        key = _ed25519_from_pkcs8(key_pem)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"{key_path}: not an Ed25519 private key")
    cert = x509.load_pem_x509_certificate(_read_pem(cert_path.read_bytes()))
    # sanity: the key must match the certificate's public key
    kb = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    cb = _spki_der(cert)
    if kb != cb:
        raise ValueError(f"{key_path} does not match {cert_path}")
    return Identity(
        key=key, cert=cert, fingerprint=fingerprint_of_cert(cert),
        key_path=key_path, cert_path=cert_path,
    )


def save_identity(directory: PathLike, identity: Identity, name: str) -> tuple[Path, Path]:
    """Persist an identity as ``<name>.key.pem`` / ``<name>.crt.pem`` plus an
    ``<name>.identity.json`` descriptor. Returns (key_path, cert_path)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / f"{name}.key.pem"
    cert_path = directory / f"{name}.crt.pem"
    key_path.write_bytes(identity.key_pem)
    cert_path.write_bytes(identity.cert_pem)
    (directory / f"{name}.identity.json").write_text(
        json.dumps(
            {
                "name": name,
                "fingerprint": identity.fingerprint,
                "key": str(key_path),
                "cert": str(cert_path),
            },
            indent=2,
        )
        + "\n"
    )
    return key_path, cert_path


def normalize_fingerprint(text: str) -> str:
    """Accept flexible fingerprint inputs and return the canonical form.

    Accepted: ``sha256:<hex>``, bare 64-char hex, a path to a certificate PEM
    or a public-key (SPKI) PEM file, or PEM text starting with ``-----BEGIN``.
    """
    s = text.strip()
    if s.lower().startswith("sha256:"):
        h = re.sub(r"[:\s]", "", s[len("sha256:") :]).lower()
        if _FP_RE.match(h):
            return f"sha256:{h}"
        raise ValueError(f"bad sha256 fingerprint: {s}")
    if _FP_RE.match(s.lower()):
        return f"sha256:{s.lower()}"
    # A path (or pasted PEM) to a certificate or public key.
    if s.startswith("-----BEGIN") or Path(s).exists():
        data = _read_pem(s.encode() if s.startswith("-----BEGIN") else Path(s).read_bytes())
        try:
            cert = x509.load_pem_x509_certificate(data)
            return fingerprint_of_cert(cert)
        except ValueError:
            pass
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            pub = load_pem_public_key(data)
            spki = pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return fingerprint_of_spki(spki)
        except Exception:
            pass
    raise ValueError(f"unrecognized fingerprint format: {text!r}")
