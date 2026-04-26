package network

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
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

func TestLoadOrCreateCAConcurrentCallersReuseSingleCA(t *testing.T) {
	dir := t.TempDir()

	const callers = 8
	results := make(chan *CA, callers)
	errs := make(chan error, callers)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			ca, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
			if err != nil {
				errs <- err
				return
			}
			results <- ca
		}()
	}

	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("LoadOrCreateCA() error = %v", err)
	}

	var first *CA
	for ca := range results {
		if first == nil {
			first = ca
			continue
		}
		if !bytes.Equal(first.CertPEM, ca.CertPEM) {
			t.Fatal("expected concurrent callers to observe the same CA certificate")
		}
		if !bytes.Equal(first.KeyPEM, ca.KeyPEM) {
			t.Fatal("expected concurrent callers to observe the same CA key")
		}
	}

	if first == nil {
		t.Fatal("expected at least one CA result")
	}

	assertCertificateMatchesKey(t, first.CertPEM, first.KeyPEM)
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
