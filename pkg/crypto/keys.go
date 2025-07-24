package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateRSAKey generates an RSA private key of the specified bit size
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// EncodePrivateKeyPEM encodes an RSA private key as PEM
func EncodePrivateKeyPEM(key *rsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %v", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// GenerateSelfSignedCert generates a self-signed certificate
func GenerateSelfSignedCert(key *rsa.PrivateKey, commonName string, dnsNames []string, validity time.Duration) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"fapictl"},
			OrganizationalUnit: []string{"Testing"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Add localhost IP addresses
	template.IPAddresses = []net.IP{
		net.IPv4(127, 0, 0, 1),
		net.IPv6loopback,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	return cert, nil
}

// EncodeCertificatePEM encodes a certificate as PEM
func EncodeCertificatePEM(cert *x509.Certificate) (string, error) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return string(pem.EncodeToMemory(block)), nil
}
