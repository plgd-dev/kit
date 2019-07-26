package generateCertificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"
)

func GenerateSelfSignedCertificate(cfg Configuration, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(cfg.ValidFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	ku, err := cfg.X509KeyUsages()
	if err != nil {
		return nil, err
	}
	ekus, uekus, err := cfg.X509ExtKeyUsages()
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber:       serialNumber,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		Subject:            cfg.ToPkixName(),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyUsage:           ku,
		ExtKeyUsage:        ekus,
		UnknownExtKeyUsage: uekus,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), nil
}
