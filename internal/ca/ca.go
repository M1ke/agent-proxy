// Package ca generates and holds the local certificate authority used to
// intercept TLS, plus a cache of per-host leaf certificates signed by it.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CA struct {
	dir     string
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func (c *CA) CertPath() string { return filepath.Join(c.dir, "ca.crt") }
func (c *CA) KeyPath() string  { return filepath.Join(c.dir, "ca.key") }
func (c *CA) PEM() []byte      { return c.certPEM }

// Load reads the CA from dir, generating it on first use.
func Load(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &CA{dir: dir, leaves: map[string]*tls.Certificate{}}
	if _, err := os.Stat(c.CertPath()); os.IsNotExist(err) {
		if err := c.generate(); err != nil {
			return nil, fmt.Errorf("generating CA: %w", err)
		}
	}
	return c, c.load()
}

func (c *CA) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "agent-proxy local CA",
			Organization: []string{"agent-proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(c.CertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return writeFile(c.KeyPath(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

func (c *CA) load() error {
	certPEM, err := os.ReadFile(c.CertPath())
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(c.KeyPath())
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA key is not ECDSA")
	}
	c.cert, c.key, c.certPEM = cert, key, certPEM
	return nil
}

// TLSConfig serves leaf certs minted on demand for whatever SNI arrives.
// http/1.1 only: declining to advertise h2 makes browsers downgrade, which
// keeps the intercepting side a plain HTTP/1.1 server.
func (c *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.LeafFor(hello.ServerName)
		},
	}
}

func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	if host == "" {
		host = "localhost"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}
	leaf, err := c.mint(host)
	if err != nil {
		return nil, err
	}
	c.leaves[host] = leaf
	return leaf, nil
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"agent-proxy"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: tmpl}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
