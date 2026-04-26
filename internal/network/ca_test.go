package network

import (
	"bytes"
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
