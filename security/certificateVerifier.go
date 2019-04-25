package security

import (
	"crypto/x509"
	"fmt"
	"net"
)

// CertificateVerifier defines interface to verify certificate EKU, revocations and other staff of the certificate.
type CertificateVerifier interface {
	Verify(conn net.Conn, certificate *x509.Certificate) error
}

type clientCertificateVerifierOptions struct {
}

// ClientCertificateVerifierOption configures how we set up the connection.
type ClientCertificateVerifierOption interface {
	apply(*clientCertificateVerifierOptions)
}

// ClientCertificateVerifier verifies client certificate
type ClientCertificateVerifier struct {
}

// NewClientCertificateVerifier creates ClientCertificateVerifier
func NewClientCertificateVerifier(opts ...ClientCertificateVerifierOption) (*ClientCertificateVerifier, error) {
	return &ClientCertificateVerifier{}, nil
}

// Verify verifies client certificate
func (c *ClientCertificateVerifier) Verify(conn net.Conn, certificate *x509.Certificate) error {
	// verify EKU
	for _, eku := range certificate.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return nil
		}
	}
	return fmt.Errorf("invalid certificate: ExtKeyUsageClientAuth not found")
}

type serverCertificateVerifierOptions struct {
}

// ServerCertificateVerifierOption configures how we set up the connection.
type ServerCertificateVerifierOption interface {
	apply(*clientCertificateVerifierOptions)
}

// ServerCertificateVerifier verifies server certificate
type ServerCertificateVerifier struct {
}

// NewServerCertificateVerifier creates ServerCertificateVerifier
func NewServerCertificateVerifier(opts ...ClientCertificateVerifierOption) (*ServerCertificateVerifier, error) {
	return &ServerCertificateVerifier{}, nil
}

// Verify verifies server certificate
func (c *ServerCertificateVerifier) Verify(conn net.Conn, certificate *x509.Certificate) error {
	// verify EKU
	for _, eku := range certificate.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return nil
		}
	}
	return fmt.Errorf("invalid certificate: ExtKeyUsageServerAuth not found")
}
