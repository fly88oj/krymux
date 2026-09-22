//! Ed25519 identities: keypair generation, self-signed certificates, and the
//! canonical fingerprint used for whitelisting and pinning.
//!
//! The canonical identity of a peer is `sha256(SPKI DER)` — byte-identical to
//! the Node implementation's fingerprint, so whitelists and pins transfer 1:1
//! between the two implementations.

use anyhow::{anyhow, bail, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// DER: fixed SPKI prefix for Ed25519 (RFC 8410) + 32-byte raw key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Builds the DER SubjectPublicKeyInfo for a raw 32-byte Ed25519 public key.
pub fn spki_from_ed25519_raw(raw: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + raw.len());
    v.extend_from_slice(&ED25519_SPKI_PREFIX);
    v.extend_from_slice(raw);
    v
}

/// Computes the canonical `sha256:<hex>` fingerprint of an SPKI DER blob.
pub fn fingerprint_of_spki(spki: &[u8]) -> String {
    let h = Sha256::digest(spki);
    format!("sha256:{}", hex::encode(h))
}

// ---------------- minimal DER walker to extract the SPKI TLV ----------------

/// Parse one DER TLV header at `off`; returns (tag, content_len, header_len).
fn tlv_header(buf: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    if off + 2 > buf.len() {
        return None;
    }
    let tag = buf[off];
    let first = buf[off + 1];
    let mut p = off + 2;
    let content_len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || p + n > buf.len() {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | buf[p + i] as usize;
        }
        p += n;
        v
    };
    Some((tag, content_len, p - off))
}

/// Direct children of the TLV at [start, end) as (offset, total_len) pairs.
fn der_children(buf: &[u8], content_start: usize, content_end: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut off = content_start;
    while off < content_end {
        let Some((_, content_len, header_len)) = tlv_header(buf, off) else {
            break;
        };
        let total = header_len + content_len;
        if off + total > content_end {
            break;
        }
        out.push((off, total));
        off += total;
    }
    out
}

/// Extract the full SPKI TLV from an Ed25519 X.509 certificate DER.
pub fn extract_ed25519_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let Some((_, clen, hlen)) = tlv_header(cert_der, 0) else {
        bail!("cert: bad outer header");
    };
    let top = der_children(cert_der, hlen, hlen + clen);
    let (tbs_off, tbs_total) = *top.first().ok_or_else(|| anyhow!("cert: no TBS element"))?;
    let tbs = &cert_der[tbs_off..tbs_off + tbs_total];
    let Some((_, tbs_clen, tbs_hlen)) = tlv_header(tbs, 0) else {
        bail!("cert: bad tbs header");
    };
    let children = der_children(tbs, tbs_hlen, tbs_hlen + tbs_clen);
    // children: [0]version?, serial, sig, issuer, validity, subject, spki, ...
    let mut idx = 0;
    if let Some((s, _)) = children.first() {
        if tbs[*s] == 0xa0 {
            idx = 1;
        }
    }
    let spki_pos = idx + 5;
    let (s, l) = *children
        .get(spki_pos)
        .ok_or_else(|| anyhow!("cert: no SPKI element"))?;
    let spki = tbs[s..s + l].to_vec();
    // sanity: must contain the Ed25519 OID 1.3.101.112
    if !spki.windows(5).any(|w| w == [0x06, 0x03, 0x2b, 0x65, 0x70]) {
        bail!("cert: SPKI is not Ed25519");
    }
    Ok(spki)
}

/// Computes the canonical fingerprint of an Ed25519 X.509 certificate by
/// extracting its SPKI.
pub fn fingerprint_of_cert(cert_der: &[u8]) -> Result<String> {
    let spki = extract_ed25519_spki(cert_der)?;
    Ok(fingerprint_of_spki(&spki))
}

// ---------------- identity generation / persistence ----------------

/// A freshly generated identity: key pair, self-signed certificate, and
/// fingerprint.
pub struct Identity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
}

/// Generates a new Ed25519 identity; `cn` seeds the certificate common name.
pub fn generate_identity(cn: &str) -> Result<Identity> {
    // explicit Ed25519 — rcgen's generate() defaults to ECDSA P-256
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generate Ed25519 key")?;
    let fingerprint = {
        let spki = spki_from_ed25519_raw(key_pair.public_key_raw());
        fingerprint_of_spki(&spki)
    };
    let short: String = fingerprint
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect();
    let mut params =
        CertificateParams::new(vec!["krymux".to_string()]).context("certificate params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{} {}", cn, short));
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2049, 12, 31);
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign certificate")?;
    let cert_der = cert.der().clone();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow!("reparse generated key: {e}"))?
        .clone_key();
    Ok(Identity {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
        fingerprint,
    })
}

/// An identity loaded from PEM files on disk.
pub struct LoadedIdentity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub fingerprint: String,
}

/// Loads a key/certificate PEM pair and derives its fingerprint.
pub fn load_identity(key_path: &Path, cert_path: &Path) -> Result<LoadedIdentity> {
    let key_der = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("read key {}", key_path.display()))?
        .clone_key();
    let cert_der = CertificateDer::from_pem_file(cert_path)
        .with_context(|| format!("read cert {}", cert_path.display()))?
        .into_owned();
    let fingerprint = fingerprint_of_cert(cert_der.as_ref())?;
    Ok(LoadedIdentity {
        cert_der,
        key_der,
        fingerprint,
    })
}

/// Persists an identity under `dir` as `<name>.key.pem` / `<name>.crt.pem`
/// plus an `<name>.identity.json` descriptor (key file chmod 600 on Unix).
/// Returns the key and cert paths.
pub fn save_identity(dir: &Path, id: &Identity, name: &str) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir)?;
    let key_path = dir.join(format!("{}.key.pem", name));
    let cert_path = dir.join(format!("{}.crt.pem", name));
    std::fs::write(&key_path, &id.key_pem)?;
    std::fs::write(&cert_path, &id.cert_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", key_path.display()))?;
    }
    let meta = serde_json::json!({
        "name": name,
        "fingerprint": id.fingerprint,
        "key": key_path.display().to_string(),
        "cert": cert_path.display().to_string(),
    });
    std::fs::write(
        dir.join(format!("{}.identity.json", name)),
        serde_json::to_string_pretty(&meta)?,
    )?;
    Ok((key_path, cert_path))
}

/// Accept flexible fingerprint inputs: `sha256:<hex>`, bare hex (64), or a path
/// to a certificate / public key PEM file.
pub fn normalize_fingerprint(input: &str) -> Result<String> {
    let s = input.trim();
    if let Some(hexpart) = s.strip_prefix("sha256:") {
        let h: String = hexpart.chars().filter(|c| *c != ':' && *c != ' ').collect();
        let h = h.to_lowercase();
        if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(format!("sha256:{}", h));
        }
        bail!("bad sha256 fingerprint: {}", s);
    }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(format!("sha256:{}", s.to_lowercase()));
    }
    let path = Path::new(s);
    if s.starts_with("-----BEGIN") || path.exists() {
        if let Ok(cert) = CertificateDer::from_pem_file(path) {
            return fingerprint_of_cert(cert.as_ref());
        }
        if let Ok(spki) = SubjectPublicKeyInfoDer::from_pem_file(path) {
            return Ok(fingerprint_of_spki(spki.as_ref()));
        }
    }
    bail!("unrecognized fingerprint format");
}
