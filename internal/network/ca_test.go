package network

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreateCAReusesExistingCertificate(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateCA(CAOptions{
		Dir:  dir,
		Name: "keel-local-ca",
	})
	if err != nil {
		t.Fatalf("LoadOrCreateCA(first) error = %v", err)
	}

	second, err := LoadOrCreateCA(CAOptions{
		Dir:  dir,
		Name: "keel-local-ca",
	})
	if err != nil {
		t.Fatalf("LoadOrCreateCA(second) error = %v", err)
	}

	if !bytes.Equal(first.CertPEM, second.CertPEM) {
		t.Fatal("expected CA certificate reuse")
	}
	if !bytes.Equal(first.KeyPEM, second.KeyPEM) {
		t.Fatal("expected CA key reuse")
	}

	assertCertificateMatchesKey(t, first.CertPEM, first.KeyPEM)
	assertCertificateMatchesKey(t, second.CertPEM, second.KeyPEM)
}

func TestIssueLeafReusesCachedCertificate(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	first, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	second, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.CertPEM, second.CertPEM) {
		t.Fatal("expected leaf certificate reuse")
	}
	if !bytes.Equal(first.KeyPEM, second.KeyPEM) {
		t.Fatal("expected leaf key reuse")
	}

	assertCertificateMatchesKey(t, first.CertPEM, first.KeyPEM)
}

func TestIssueLeafCertificateIncludesRequestedHostname(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(CAOptions{
		Dir:  dir,
		Name: "keel-local-ca",
	})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := leaf.X509()
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.VerifyHostname("api.github.com"); err != nil {
		t.Fatalf("VerifyHostname() error = %v", err)
	}
}

func TestIssueLeafRegeneratesWhenCachedKeyIsMissing(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	first, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "issued", "api.github.com.key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	second, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first.CertPEM, second.CertPEM) {
		t.Fatal("expected missing-key cache regeneration")
	}

	assertIssuedChainsToCA(t, ca, second)
	assertCertificateMatchesKey(t, second.CertPEM, second.KeyPEM)
}

func TestIssueLeafRegeneratesWhenCachedLeafUsesDifferentCA(t *testing.T) {
	dir := t.TempDir()

	firstCA, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	staleLeaf, err := firstCA.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	otherDir := t.TempDir()
	secondCA, err := LoadOrCreateCA(CAOptions{Dir: otherDir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), secondCA.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), secondCA.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	currentCA, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	currentLeaf, err := currentCA.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(staleLeaf.CertPEM, currentLeaf.CertPEM) {
		t.Fatal("expected stale cached leaf regeneration")
	}

	assertIssuedChainsToCA(t, currentCA, currentLeaf)
	assertCertificateMatchesKey(t, currentLeaf.CertPEM, currentLeaf.KeyPEM)
}

func TestIssueLeafChainsToCurrentCA(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	assertIssuedChainsToCA(t, ca, leaf)
}

func TestLoadOrCreateCAReloadsOnDiskWinnerWhenFilesChange(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	otherDir := t.TempDir()
	winner, err := LoadOrCreateCA(CAOptions{Dir: otherDir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), winner.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), winner.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first.CertPEM, reloaded.CertPEM) {
		t.Fatal("expected CA reload to return the on-disk winner")
	}
	if !bytes.Equal(winner.CertPEM, reloaded.CertPEM) {
		t.Fatal("expected CA reload to reuse on-disk winner certificate")
	}
	if !bytes.Equal(winner.KeyPEM, reloaded.KeyPEM) {
		t.Fatal("expected CA reload to reuse on-disk winner key")
	}
}

func TestIssueLeafReloadsOnDiskWinnerWhenFilesChange(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	first, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	otherLeaf, err := createTestLeafForCA(ca, "api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "issued", "api.github.com.crt"), otherLeaf.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "issued", "api.github.com.key"), otherLeaf.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first.CertPEM, reloaded.CertPEM) {
		t.Fatal("expected leaf reload to return the on-disk winner")
	}
	if !bytes.Equal(otherLeaf.CertPEM, reloaded.CertPEM) {
		t.Fatal("expected leaf reload to reuse on-disk winner certificate")
	}
	if !bytes.Equal(otherLeaf.KeyPEM, reloaded.KeyPEM) {
		t.Fatal("expected leaf reload to reuse on-disk winner key")
	}

	assertIssuedChainsToCA(t, ca, reloaded)
}

func TestFileLockUnlockDoesNotReleaseAnotherOwner(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "cache.lock")

	first, err := acquireFileLock(lockPath)
	if err != nil {
		t.Fatalf("acquireFileLock(first) error = %v", err)
	}

	secondReady := make(chan *fileLock, 1)
	secondErr := make(chan error, 1)
	go func() {
		lock, err := acquireFileLock(lockPath)
		if err != nil {
			secondErr <- err
			return
		}
		secondReady <- lock
	}()

	select {
	case err := <-secondErr:
		t.Fatalf("acquireFileLock(second) error = %v", err)
	case <-secondReady:
		t.Fatal("expected second lock acquisition to block while first owner holds lock")
	case <-time.After(100 * time.Millisecond):
	}

	if err := first.Unlock(); err != nil {
		t.Fatalf("first.Unlock() error = %v", err)
	}

	var second *fileLock
	select {
	case err := <-secondErr:
		t.Fatalf("acquireFileLock(second) error = %v", err)
	case second = <-secondReady:
	case <-time.After(time.Second):
		t.Fatal("expected second owner to acquire lock after first unlock")
	}

	if err := first.Unlock(); err != nil {
		t.Fatalf("first.Unlock(second time) error = %v", err)
	}

	thirdReady := make(chan *fileLock, 1)
	thirdErr := make(chan error, 1)
	go func() {
		lock, err := acquireFileLock(lockPath)
		if err != nil {
			thirdErr <- err
			return
		}
		thirdReady <- lock
	}()

	select {
	case err := <-thirdErr:
		t.Fatalf("acquireFileLock(third) error = %v", err)
	case lock := <-thirdReady:
		_ = lock.Unlock()
		t.Fatal("expected stale unlock from first owner to not release second owner's lock")
	case <-time.After(100 * time.Millisecond):
	}

	if err := second.Unlock(); err != nil {
		t.Fatalf("second.Unlock() error = %v", err)
	}

	select {
	case err := <-thirdErr:
		t.Fatalf("acquireFileLock(third) error = %v", err)
	case third := <-thirdReady:
		if err := third.Unlock(); err != nil {
			t.Fatalf("third.Unlock() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected third owner to acquire lock after second unlock")
	}
}

func assertIssuedChainsToCA(t *testing.T, ca *CA, issued *IssuedCert) {
	t.Helper()

	caCert, err := parseCertificate(ca.CertPEM)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafCert, err := issued.X509()
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		DNSName: "api.github.com",
		Roots:   roots,
	}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func assertCertificateMatchesKey(t *testing.T, certPEM, keyPEM []byte) {
	t.Helper()

	cert, err := parseCertificate(certPEM)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("decode private key pem")
		return
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	certKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T", cert.PublicKey)
	}
	if certKey.N.Cmp(key.N) != 0 || certKey.E != key.E {
		t.Fatal("certificate public key does not match private key")
	}
}

func createTestLeafForCA(ca *CA, host string) (*IssuedCert, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().UTC().Add(-time.Hour),
		NotAfter:    time.Now().UTC().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}

	return &IssuedCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}, nil
}
