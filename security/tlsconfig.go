package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/go-ocf/kit/security/generateCertificate"
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

func generateClientSelfSignedCertificate(validFor time.Duration) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	var cfg generateCertificate.Configuration
	cfg.Subject.CommonName = "client self-signed certificate"
	cfg.KeyUsages = []string{"digitalSignature, keyAgreement"}
	cfg.ExtensionKeyUsages = []string{"client"}
	cfg.ValidFor = validFor
	cert, err := generateCertificate.GenerateSelfSignedCertificate(cfg, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	privKey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKey})

	return tls.X509KeyPair(cert, privKeyPEM)
}

func NewTLSConfigWithClientSelfSignedCertificate(validFor time.Duration, cas []*x509.Certificate, verifyPeerCertificate VerifyPeerCertificateFunc) (*tls.Config, error) {
	cert, err := generateClientSelfSignedCertificate(validFor)
	if err != nil {
		return nil, err
	}
	return NewTLSConfig(cert, cas, verifyPeerCertificate), nil
}

// NewTLSConfigWithoutPeerVerification creates tls.Config without verify client certificate.
func NewTLSConfigWithoutPeerVerification(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{cert},
	}
}

// NewTLSConfig creates tls.Config with veryfication of client certificate.
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
