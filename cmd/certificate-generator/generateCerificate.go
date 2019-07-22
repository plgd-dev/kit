package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	ocfSigner "github.com/go-ocf/kit/security/signer"
)

func createCSR(opts Options, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	//create the csr
	subj := opts.ToPkixName()

	extensionKeyUsages, err := opts.ToExtensionKeyUsages()
	if err != nil {
		return nil, err
	}

	val, err := asn1.Marshal(extensionKeyUsages)
	if err != nil {
		return nil, err
	}

	bcVal, err := asn1.Marshal(basicConstraints{false})
	if err != nil {
		return nil, err
	}

	kuVal, err := asn1.Marshal(asn1.BitString{[]byte{1<<3 | 1<<7}, 7}) //x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	if err != nil {
		return nil, err
	}

	ips, err := opts.ToIPAddresses()
	if err != nil {
		return nil, err
	}

	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:  asn1Subj,
		DNSNames:    opts.Certificate.SubjectAlternativeName.DNSNames,
		IPAddresses: ips,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, //basic constraints
				Value:    bcVal,
				Critical: false,
			},
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, //key usage
				Value:    kuVal,
				Critical: false,
			},
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, //EKU
				Value:    val,
				Critical: false,
			},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func generateCert(opts Options, privateKey *ecdsa.PrivateKey, signerCA []*x509.Certificate, signerCAKey *ecdsa.PrivateKey) ([]byte, error) {
	csr, err := createCSR(opts, privateKey)
	if err != nil {
		return nil, err
	}

	s := ocfSigner.NewBasicCertificateSigner(signerCA, signerCAKey, opts.Certificate.ValidFor)
	return s.Sign(context.Background(), csr)
}
