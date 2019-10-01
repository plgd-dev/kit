package security

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"
)

// TLSConfig set configuration.
type TLSConfig struct {
	Certificate    string `envconfig:"CERTIFICATE"`           // file path to PEM encoded cert/cert chain
	CertificateKey string `envconfig:"CERTIFICATE_KEY"`       // file path to PEM encoded private key
	CAPool         string `envconfig:"CERTIFICATE_AUTHORITY"` // file path to PEM encoded ca pool
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
		return nil, fmt.Errorf("cannot load ca '%v': %v", config.CAPool, err)
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

// NewTLSConfigWithoutPeerVerification creates tls.Config without verify client certificate.
func NewTLSConfigWithoutPeerVerification(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		ClientAuth:               tls.NoClientCert,
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
}

// NewDefaultCertPool loads system CAs and add custom CAs to cert pool.
func NewDefaultCertPool(cas []*x509.Certificate) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, ca := range cas {
		pool.AddCert(ca)
	}
	return pool
}

// NewDefaultTLSConfig return default *tls.Config with system CAs and add custom CAs to cert pool.
func NewDefaultTLSConfig(cas []*x509.Certificate) *tls.Config {
	pool := NewDefaultCertPool(cas)
	return &tls.Config{
		RootCAs:                  pool,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
}

// NewTLSConfig creates tls.Config with veryfication of client certificate.
func NewTLSConfig(cert tls.Certificate, cas []*x509.Certificate, verifyPeerCertificate VerifyPeerCertificateFunc) *tls.Config {
	caPool := NewDefaultCertPool(cas)
	return &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
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
