package generateCertificate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func newCert(cfg Configuration) (*x509.Certificate, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(cfg.ValidFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               cfg.ToPkixName(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA: true,
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

func createPemChain(intermedateCAs []*x509.Certificate, cert []byte) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 2048))

	// encode cert
	err := pem.Encode(buf, &pem.Block{
		Type: "CERTIFICATE", Bytes: cert,
	})
	if err != nil {
		return nil, err
	}
	// encode intermediates
	for _, ca := range intermedateCAs {
		if bytes.Equal(ca.RawIssuer, ca.RawSubject) {
			continue
		}
		err := pem.Encode(buf, &pem.Block{
			Type: "CERTIFICATE", Bytes: ca.Raw,
		})
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func GenerateIntermediateCA(cfg Configuration, privateKey *ecdsa.PrivateKey, signerCA []*x509.Certificate, signerCAKey *ecdsa.PrivateKey) ([]byte, error) {
	cacert, err := newCert(cfg)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, cacert, signerCA[0], &privateKey.PublicKey, signerCAKey)
	if err != nil {
		return nil, err
	}
	return createPemChain(signerCA, der)

}
