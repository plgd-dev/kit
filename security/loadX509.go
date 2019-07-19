package security

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// LoadX509 loads certificates from file in PEM format
func LoadX509(path string) ([]*x509.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil {
		return nil, fmt.Errorf("cannot decode pem block")
	}
	certs, err := x509.ParseCertificates(certDERBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// LoadX509PrivateKey loads private key from file in PEM format
func LoadX509PrivateKey(path string) (*ecdsa.PrivateKey, error) {
	certPEMBlock, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil {
		return nil, fmt.Errorf("cannot decode pem block")
	}

	if key, err := x509.ParsePKCS8PrivateKey(certDERBlock.Bytes); err == nil {
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(certDERBlock.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}
