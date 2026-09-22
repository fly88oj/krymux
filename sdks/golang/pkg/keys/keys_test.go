package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFingerprintDeterministicAcrossImplementations(t *testing.T) {
	id, err := GenerateIdentity("test")
	if err != nil {
		t.Fatal(err)
	}
	// Recompute the fingerprint the way the Rust SDK does: an explicit
	// RFC 8410 SPKI prefix + raw key, hashed with SHA-256.
	pub, ok := id.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("not an ed25519 key")
	}
	prefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	spki := append(append([]byte{}, prefix...), pub...)
	sum := sha256.Sum256(spki)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if id.Fingerprint != want {
		t.Fatalf("fingerprint mismatch: %s vs rust-style %s", id.Fingerprint, want)
	}
	// and the certificate SPKI must hash to the same value
	fpCert, err := FingerprintOfCertDER(id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if fpCert != want {
		t.Fatalf("cert fingerprint %s != key fingerprint %s", fpCert, want)
	}
}

func TestCertificateShape(t *testing.T) {
	id, err := GenerateIdentity("cn-test")
	if err != nil {
		t.Fatal(err)
	}
	cert := id.Certificate
	if !strings.HasPrefix(cert.Subject.CommonName, "cn-test ") {
		t.Fatalf("CN %q must embed the cn", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "krymux" {
		t.Fatalf("SAN %v, want [krymux]", cert.DNSNames)
	}
	if !time.Now().After(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		t.Fatal("certificate must be valid now")
	}
	// verify the self-signature directly (CheckSignatureFrom additionally
	// demands CA:TRUE, which a leaf identity deliberately does not carry)
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("self-signature invalid: %v", err)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	id, err := GenerateIdentity("roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath, err := SaveIdentity(dir, id, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(keyPath) != "alice.key.pem" || filepath.Base(certPath) != "alice.crt.pem" {
		t.Fatalf("rust-compatible file names expected, got %s %s", keyPath, certPath)
	}
	loaded, err := LoadIdentity(keyPath, certPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != id.Fingerprint {
		t.Fatalf("fingerprint changed across save/load: %s vs %s", loaded.Fingerprint, id.Fingerprint)
	}
	if !loaded.PrivateKey.Equal(id.PrivateKey) {
		t.Fatal("private key changed across save/load")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	id, _ := GenerateIdentity("norm")
	fp := id.Fingerprint
	bare := strings.TrimPrefix(fp, "sha256:")
	if got, err := NormalizeFingerprint(fp); err != nil || got != fp {
		t.Fatalf("sha256 form: %v %v", got, err)
	}
	if got, err := NormalizeFingerprint(bare); err != nil || got != fp {
		t.Fatalf("bare hex: %v %v", got, err)
	}
	if got, err := NormalizeFingerprint(strings.ToUpper(bare)); err != nil || got != fp {
		t.Fatalf("uppercase hex: %v %v", got, err)
	}
	if _, err := NormalizeFingerprint("sha256:zz"); err == nil {
		t.Fatal("garbage must be rejected")
	}
	if _, err := NormalizeFingerprint("definitely-not-a-fingerprint"); err == nil {
		t.Fatal("garbage must be rejected")
	}
	// a certificate PEM text and a cert file path both resolve
	if got, err := NormalizeFingerprint(string(id.CertPEM)); err != nil || got != fp {
		t.Fatalf("cert pem: %v %v", got, err)
	}
}

func TestRejectNonEd25519Certificate(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FingerprintOfCertDER(der); err == nil {
		t.Fatal("non-Ed25519 certificate must be rejected")
	}
}
