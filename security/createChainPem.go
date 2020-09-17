package security

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

// CreatePemChain creates chain of PEM certificates.
func CreatePemChain(intermedateCAs []*x509.Certificate, cert []byte) ([]byte, error) {
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
		err := pem.Encode(buf, &pem.Block{
			Type: "CERTIFICATE", Bytes: ca.Raw,
		})
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
