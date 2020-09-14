package generateCertificate

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
)

func newCert(cfg Configuration) (*x509.Certificate, error) {
	notBefore, err := cfg.ToValidFrom()
	if err != nil {
		return nil, err
	}
	notAfter := notBefore.Add(cfg.ValidFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               cfg.ToPkixName(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if cfg.BasicConstraints.MaxPathLen >= 0 {
		if cfg.BasicConstraints.MaxPathLen == 0 {
			template.MaxPathLenZero = true
		} else {
			template.MaxPathLen = cfg.BasicConstraints.MaxPathLen
		}
	}
	return &template, nil
}

func GenerateIntermediateCA(cfg Configuration, privateKey *ecdsa.PrivateKey, signerCA []*x509.Certificate, signerCAKey *ecdsa.PrivateKey) ([]byte, error) {
	cacert, err := newCert(cfg)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, cacert, signerCA[0], &privateKey.PublicKey, signerCAKey)
}
