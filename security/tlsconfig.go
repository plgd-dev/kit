package security

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"
)

// Generates `func IsInsecure() bool`
//go:generate go run generateInsecure.go security

// TLSConfig set configuration.
type TLSConfig struct {
	Certificate    string `envconfig:"TLS_CERTIFICATE"`
	CertificateKey string `envconfig:"TLS_CERTIFICATE_KEY"`
	CAPool         string `envconfig:"TLS_CERTIFICATE_AUTHORITY"`
}

// VerifyPeerCertificateFunc verifies content of certificate. It's called after success validation against CAs.
type VerifyPeerCertificateFunc func(verifyPeerCertificate *x509.Certificate) error

// NewTLSConfigFromConfiguration setup tls.Config that provides verification certificate with connection.
func NewTLSConfigFromConfiguration(config TLSConfig, certificateVerifier VerifyPeerCertificateFunc) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(config.Certificate, config.CertificateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot load x509 key pair('%v', '%v'): %v", config.Certificate, config.CertificateKey, err)
	}

	var caRootPool []*x509.Certificate
	certPEMBlock, err := ioutil.ReadFile(config.CAPool)
	if err != nil {
		return nil, nil
	}
	rest := certPEMBlock
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		caCert, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, nil
		}
		caRootPool = append(caRootPool, caCert...)
	}
	return NewTLSConfig(cert, caRootPool, certificateVerifier), nil
}

func NewTLSConfig(cert tls.Certificate, cas []*x509.Certificate, verifyPeerCertificate VerifyPeerCertificateFunc) *tls.Config {
	caPool := x509.NewCertPool()
	for _, ca := range cas {
		caPool.AddCert(ca)
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			intermediateCAPool := x509.NewCertPool()
			var certificate *x509.Certificate
			for _, rawCert := range rawCerts {
				certs, err := x509.ParseCertificates(rawCert)
				if err != nil {
					return err
				}
				certificate = certs[0]
				for i := 1; i < len(certs); i++ {
					intermediateCAPool.AddCert(certs[i])
				}
			}
			_, err := certificate.Verify(x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: intermediateCAPool,
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err != nil {
				return err
			}
			if verifyPeerCertificate(certificate) != nil {
				return err
			}
			return nil
		},
	}
}
