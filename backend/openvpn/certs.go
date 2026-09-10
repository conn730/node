package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// certBundle holds the PEM-encoded material an OpenVPN server config needs.
// Ported from vpn-ui's OpenVpnService.GenerateSelfSignedCA (ECDSA P-384,
// 10-year validity) — same algorithm choice, adapted to this package.
type certBundle struct {
	CaCert     string
	ServerCert string
	ServerKey  string
	TlsCrypt   string
}

// generateSelfSignedCA creates a fresh CA + server certificate + tls-crypt
// static key. There is no client certificate: the server runs with
// verify-client-cert none and authenticates by username/password instead
// (see authstore.go), matching every other legacy-protocol account model
// this fork already uses.
func generateSelfSignedCA() (*certBundle, error) {
	caPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"pasarguard-node"}, CommonName: "pasarguard-node OpenVPN CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caCert, _ := x509.ParseCertificate(caCertDER)

	serverPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"pasarguard-node"}, CommonName: "pasarguard-node OpenVPN Server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverPriv)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	tlsCrypt, err := generateTlsCryptKey()
	if err != nil {
		return nil, fmt.Errorf("generate tls-crypt key: %w", err)
	}

	return &certBundle{
		CaCert:     string(caCertPEM),
		ServerCert: string(serverCertPEM),
		ServerKey:  string(serverKeyPEM),
		TlsCrypt:   tlsCrypt,
	}, nil
}

// generateTlsCryptKey generates an OpenVPN static key v1 (256 random bytes,
// hex-dumped 16 bytes/line between the standard markers).
func generateTlsCryptKey() (string, error) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	var b []byte
	b = append(b, []byte("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")...)
	for i := 0; i < len(key); i += 16 {
		end := i + 16
		if end > len(key) {
			end = len(key)
		}
		b = append(b, []byte(fmt.Sprintf("%x\n", key[i:end]))...)
	}
	b = append(b, []byte("-----END OpenVPN Static key V1-----\n")...)
	return string(b), nil
}

// certPaths returns the on-disk paths certBundle.writeTo wrote to.
func certPaths(dir string) (ca, cert, key, tc string) {
	return filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "tc.key")
}

// loadOrCreateCerts reuses a previously generated bundle from dir, or
// generates and persists a new one. Reusing across restarts matters: a
// regenerated CA would invalidate every client profile already handed out.
func loadOrCreateCerts(dir string) error {
	caPath, certPath, keyPath, tcPath := certPaths(dir)
	if fileExists(caPath) && fileExists(certPath) && fileExists(keyPath) && fileExists(tcPath) {
		return nil
	}

	bundle, err := generateSelfSignedCA()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	writes := []struct {
		path    string
		content string
		mode    os.FileMode
	}{
		{caPath, bundle.CaCert, 0644},
		{certPath, bundle.ServerCert, 0644},
		{keyPath, bundle.ServerKey, 0600},
		{tcPath, bundle.TlsCrypt, 0600},
	}
	for _, w := range writes {
		if err := os.WriteFile(w.path, []byte(w.content), w.mode); err != nil {
			return fmt.Errorf("write %s: %w", w.path, err)
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
