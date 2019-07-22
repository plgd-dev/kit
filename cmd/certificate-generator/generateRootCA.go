package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

func generateRootCA(opts Options, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	cacert, err := newCert(opts)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, cacert, cacert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil

}
