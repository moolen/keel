package network

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var caMu sync.Mutex

type CAOptions struct {
	Dir  string
	Name string
}

type CA struct {
	CertPEM []byte
	KeyPEM  []byte
	cert    *x509.Certificate
	key     crypto.Signer
	dir     string
}

type IssuedCert struct {
	CertPEM []byte
	KeyPEM  []byte
}

type fileLock struct {
	file *os.File
	mu   sync.Mutex
	done bool
}

func LoadOrCreateCA(opts CAOptions) (*CA, error) {
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}

	certPath := filepath.Join(opts.Dir, "ca.crt")
	keyPath := filepath.Join(opts.Dir, "ca.key")
	lockPath := filepath.Join(opts.Dir, "ca.lock")

	caMu.Lock()
	defer caMu.Unlock()

	if ca, ok, err := loadCAIfUsable(certPath, keyPath, opts.Dir); err != nil {
		return nil, err
	} else if ok {
		return ca, nil
	}

	var loaded *CA
	if err := withFileLock(lockPath, func() error {
		if ca, ok, err := loadCAIfUsable(certPath, keyPath, opts.Dir); err != nil {
			return err
		} else if ok {
			loaded = ca
			return nil
		}

		if err := createCA(certPath, keyPath, opts); err != nil {
			return err
		}

		ca, ok, err := loadCAIfUsable(certPath, keyPath, opts.Dir)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("load persisted ca")
		}

		loaded = ca
		return nil
	}); err != nil {
		return nil, err
	}

	return loaded, nil
}

func (ca *CA) IssueLeaf(host string) (*IssuedCert, error) {
	host = normalizeName(host)
	issuedDir := filepath.Join(ca.dir, "issued")
	if err := os.MkdirAll(issuedDir, 0o700); err != nil {
		return nil, err
	}

	caMu.Lock()
	defer caMu.Unlock()

	certPath := filepath.Join(issuedDir, host+".crt")
	keyPath := filepath.Join(issuedDir, host+".key")
	lockPath := filepath.Join(issuedDir, host+".lock")
	if issued, ok, err := loadIssuedCertIfUsable(certPath, keyPath, host, ca.cert); err != nil {
		return nil, err
	} else if ok {
		return issued, nil
	}

	var loaded *IssuedCert
	if err := withFileLock(lockPath, func() error {
		if issued, ok, err := loadIssuedCertIfUsable(certPath, keyPath, host, ca.cert); err != nil {
			return err
		} else if ok {
			loaded = issued
			return nil
		}

		if err := ca.createLeaf(certPath, keyPath, host); err != nil {
			return err
		}

		issued, ok, err := loadIssuedCertIfUsable(certPath, keyPath, host, ca.cert)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("load persisted leaf certificate")
		}

		loaded = issued
		return nil
	}); err != nil {
		return nil, err
	}

	return loaded, nil
}

func (c *IssuedCert) X509() (*x509.Certificate, error) {
	block, _ := pem.Decode(c.CertPEM)
	if block == nil {
		return nil, fmt.Errorf("decode certificate pem")
	}

	return x509.ParseCertificate(block.Bytes)
}

func loadCAIfUsable(certPath, keyPath, dir string) (*CA, bool, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, false, nil
	}

	key, err := parseSigner(keyPEM)
	if err != nil {
		return nil, false, nil
	}

	if !certificateMatchesKey(cert, key) {
		return nil, false, nil
	}

	return &CA{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		cert:    cert,
		key:     key,
		dir:     dir,
	}, true, nil
}

func createCA(certPath, keyPath string, opts CAOptions) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return err
	}

	name := opts.Name
	if name == "" {
		name = "keel-local-ca"
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Keel Local Development"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return writePEMPair(certPath, certPEM, keyPath, keyPEM)
}

func (ca *CA) createLeaf(certPath, keyPath, host string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return writePEMPair(certPath, certPEM, keyPath, keyPEM)
}

func loadIssuedCertIfUsable(certPath, keyPath, host string, caCert *x509.Certificate) (*IssuedCert, bool, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, false, nil
	}

	key, err := parseSigner(keyPEM)
	if err != nil {
		return nil, false, nil
	}

	if !certificateMatchesKey(cert, key) {
		return nil, false, nil
	}
	if !issuedCertChainsToCA(cert, host, caCert) {
		return nil, false, nil
	}

	return &IssuedCert{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, true, nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("decode certificate pem")
	}

	return x509.ParseCertificate(block.Bytes)
}

func parseSigner(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode private key pem")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func certificateMatchesKey(cert *x509.Certificate, key crypto.Signer) bool {
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return false
	}

	return publicKey.N.Cmp(privateKey.N) == 0 && publicKey.E == privateKey.E
}

func issuedCertChainsToCA(cert *x509.Certificate, host string, caCert *x509.Certificate) bool {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	_, err := cert.Verify(x509.VerifyOptions{
		DNSName: host,
		Roots:   roots,
	})
	return err == nil
}

func writePEMPair(certPath string, certPEM []byte, keyPath string, keyPEM []byte) error {
	if err := writeFileAtomically(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomically(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return nil
}

func writeFileAtomically(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}

	return nil
}

func withFileLock(lockPath string, fn func() error) error {
	lock, err := acquireFileLock(lockPath)
	if err != nil {
		return err
	}
	defer lock.Unlock()

	return fn()
}

func acquireFileLock(lockPath string) (*fileLock, error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}

	return &fileLock{file: file}, nil
}

func (l *fileLock) Unlock() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.done {
		return nil
	}

	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
		_ = l.file.Close()
		l.done = true
		return err
	}
	if err := l.file.Close(); err != nil {
		l.done = true
		return err
	}

	l.done = true
	return nil
}
