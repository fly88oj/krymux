// Package keys implements Krymux Ed25519 identities: keypair generation,
// self-signed certificates, persistence, and the canonical
// "sha256:"+hex(sha256(SPKI DER)) fingerprint used for whitelisting and
// pinning — byte-identical to the Rust implementation
// (crates/krymux/src/keys.rs), so whitelists and pins transfer 1:1.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is a Krymux identity: an Ed25519 keypair with a self-signed
// X.509 certificate and its canonical fingerprint.
type Identity struct {
	PrivateKey  ed25519.PrivateKey
	Certificate *x509.Certificate
	CertDER     []byte
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string // "sha256:<64 lowercase hex>"
}

// FingerprintOfSPKI computes the canonical "sha256:<hex>" fingerprint of an
// SPKI DER blob.
func FingerprintOfSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FingerprintOfCertDER computes the canonical fingerprint of an Ed25519
// X.509 certificate by hashing its SubjectPublicKeyInfo. Non-Ed25519
// certificates are rejected, mirroring the Rust SPKI OID check.
func FingerprintOfCertDER(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("keys: parse certificate: %w", err)
	}
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		return "", errors.New("keys: certificate public key is not Ed25519")
	}
	return FingerprintOfSPKI(cert.RawSubjectPublicKeyInfo), nil
}

// FingerprintOfCert is an alias of FingerprintOfCertDER.
func FingerprintOfCert(certDER []byte) (string, error) { return FingerprintOfCertDER(certDER) }

// GenerateIdentity generates a new Ed25519 identity. The certificate is a
// self-signed X.509 v3 with CN "<cn> <first-16-fp-hex>" and SAN "krymux",
// mirroring the shape the Rust SDK produces (the fingerprint itself covers
// only the SPKI, so it is stable across implementations).
func GenerateIdentity(cn string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: generate Ed25519 key: %w", err)
	}
	// Go marshals the Ed25519 SPKI as exactly the RFC 8410 DER
	// (30 2a 30 05 06 03 2b 65 70 03 21 00 <key>), identical to the Rust
	// ED25519_SPKI_PREFIX + raw key construction, so fingerprints match 1:1.
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal SPKI: %w", err)
	}
	fp := FingerprintOfSPKI(spki)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("keys: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s %s", cn, fp[7:7+16]),
		},
		DNSNames:              []string{"krymux"},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("keys: self-sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("keys: reparse certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal PKCS8 key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &Identity{
		PrivateKey:  priv,
		Certificate: cert,
		CertDER:     der,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: fp,
	}, nil
}

// LoadIdentity loads a key/certificate PEM pair and derives its fingerprint.
// The key must be a PKCS8 PEM ("PRIVATE KEY") holding an Ed25519 key — the
// exact format the Rust SDK (rcgen) writes.
func LoadIdentity(keyPath, certPath string) (*Identity, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("keys: read key %s: %w", keyPath, err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("keys: read cert %s: %w", certPath, err)
	}
	return ParseIdentity(keyPEM, certPEM)
}

// ParseIdentity parses key and certificate PEM buffers.
func ParseIdentity(keyPEM, certPEM []byte) (*Identity, error) {
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("keys: no PEM block in key file")
	}
	var priv ed25519.PrivateKey
	switch kb.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keys: parse PKCS8 key: %w", err)
		}
		var ok bool
		priv, ok = k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("keys: private key is not Ed25519")
		}
	case "ED25519 PRIVATE KEY", "OPENSSH PRIVATE KEY":
		return nil, fmt.Errorf("keys: unsupported key PEM type %q (want PKCS8 \"PRIVATE KEY\")", kb.Type)
	default:
		return nil, fmt.Errorf("keys: unsupported key PEM type %q", kb.Type)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("keys: no CERTIFICATE PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse certificate: %w", err)
	}
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, errors.New("keys: certificate public key is not Ed25519")
	}
	fp := FingerprintOfSPKI(cert.RawSubjectPublicKeyInfo)
	return &Identity{
		PrivateKey:  priv,
		Certificate: cert,
		CertDER:     cb.Bytes,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: fp,
	}, nil
}

// TLSCertificate returns the identity as a crypto/tls certificate pair.
func (id *Identity) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{id.CertDER},
		PrivateKey:  id.PrivateKey,
	}
}

// SaveIdentity persists the identity under dir as <name>.key.pem /
// <name>.crt.pem plus a <name>.identity.json descriptor, mirroring the Rust
// save_identity layout. Returns the key and cert paths.
func SaveIdentity(dir string, id *Identity, name string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("keys: create dir: %w", err)
	}
	keyPath := filepath.Join(dir, name+".key.pem")
	certPath := filepath.Join(dir, name+".crt.pem")
	if err := os.WriteFile(keyPath, id.KeyPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, id.CertPEM, 0o644); err != nil {
		return "", "", err
	}
	meta, _ := json.MarshalIndent(map[string]string{
		"name":        name,
		"fingerprint": id.Fingerprint,
		"key":         keyPath,
		"cert":        certPath,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, name+".identity.json"), meta, 0o644); err != nil {
		return "", "", err
	}
	return keyPath, certPath, nil
}

// NormalizeFingerprint accepts flexible fingerprint inputs: "sha256:<hex>",
// bare 64-char hex, or a path to a certificate / public key PEM file.
func NormalizeFingerprint(input string) (string, error) {
	s := strings.TrimSpace(input)
	if rest, ok := strings.CutPrefix(s, "sha256:"); ok {
		h := strings.Map(func(r rune) rune {
			if r == ':' || r == ' ' {
				return -1
			}
			return r
		}, rest)
		h = strings.ToLower(h)
		if len(h) == 64 && allHex(h) {
			return "sha256:" + h, nil
		}
		return "", fmt.Errorf("keys: bad sha256 fingerprint: %s", s)
	}
	if len(s) == 64 && allHex(s) {
		return "sha256:" + strings.ToLower(s), nil
	}
	if strings.HasPrefix(s, "-----BEGIN") {
		if fp, err := fingerprintOfPEM([]byte(s)); err == nil {
			return fp, nil
		}
		return "", errors.New("keys: unrecognized fingerprint format")
	}
	if _, err := os.Stat(s); err == nil {
		if fp, err := fingerprintOfPEMFile(s); err == nil {
			return fp, nil
		}
		return "", fmt.Errorf("keys: cannot derive fingerprint from %s", s)
	}
	return "", errors.New("keys: unrecognized fingerprint format")
}

func allHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func fingerprintOfPEMFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fingerprintOfPEM(data)
}

func fingerprintOfPEM(data []byte) (string, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return "", errors.New("keys: no PEM block")
	}
	if blk.Type == "CERTIFICATE" {
		return FingerprintOfCertDER(blk.Bytes)
	}
	if blk.Type == "PUBLIC KEY" {
		if _, err := x509.ParsePKIXPublicKey(blk.Bytes); err != nil {
			return "", err
		}
		return FingerprintOfSPKI(blk.Bytes), nil
	}
	return "", fmt.Errorf("keys: unsupported PEM type %q", blk.Type)
}
