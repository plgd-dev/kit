package generateCertificate

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

func GenerateRootCA(cfg Configuration, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	cacert, err := newCert(cfg)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, cacert, cacert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
