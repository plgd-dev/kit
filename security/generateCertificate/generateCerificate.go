package generateCertificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	ocfSigner "github.com/plgd-dev/kit/v2/security/signer"
)

// GenerateCSR creates CSR according to configuration.
func GenerateCSR(cfg Configuration, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	//create the csr
	subj := cfg.ToPkixName()

	ips, err := cfg.ToIPAddresses()
	if err != nil {
		return nil, err
	}

	extraExtensions := make([]pkix.Extension, 0, 3)
	if !cfg.BasicConstraints.Ignore {
		bcVal, err := asn1.Marshal(basicConstraints{false})
		if err != nil {
			return nil, err
		}
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, //basic constraints
			Value:    bcVal,
			Critical: false,
		})
	}

	keyUsages, err := cfg.AsnKeyUsages()
	if err != nil {
		return nil, err
	}
	if keyUsages.BitLength > 0 {
		val, err := asn1.Marshal(keyUsages)
		if err != nil {
			return nil, err
		}
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, //key usage
			Value:    val,
			Critical: false,
		})
	}

	extensionKeyUsages, err := cfg.AsnExtensionKeyUsages()
	if err != nil {
		return nil, err
	}
	if len(extensionKeyUsages) > 0 {
		val, err := asn1.Marshal(extensionKeyUsages)
		if err != nil {
			return nil, err
		}
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, //EKU
			Value:    val,
			Critical: false,
		})
	}

	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		DNSNames:           cfg.SubjectAlternativeName.DNSNames,
		IPAddresses:        ips,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	if len(extraExtensions) > 0 {
		template.ExtraExtensions = extraExtensions
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func GenerateCert(cfg Configuration, privateKey *ecdsa.PrivateKey, signerCA []*x509.Certificate, signerCAKey *ecdsa.PrivateKey) ([]byte, error) {
	csr, err := GenerateCSR(cfg, privateKey)
	if err != nil {
		return nil, err
	}

	notBefore, err := cfg.ToValidFrom()
	if err != nil {
		return nil, err
	}

	notAfter := notBefore.Add(cfg.ValidFor)
	s := ocfSigner.NewBasicCertificateSigner(signerCA, signerCAKey, notBefore, notAfter)
	return s.Sign(context.Background(), csr)
}
