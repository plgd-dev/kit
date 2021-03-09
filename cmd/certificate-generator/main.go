package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/plgd-dev/kit/security/generateCertificate"

	flags "github.com/jessevdk/go-flags"
	"github.com/plgd-dev/kit/security"
)

type Options struct {
	Command struct {
		GenerateRootCA         bool   `long:"generateRootCA"`
		GenerateIntermediateCA bool   `long:"generateIntermediateCA"`
		GenerateCert           bool   `long:"generateCertificate"`
		GenerateIdentity       string `long:"generateIdentityCertificate" description:"deviceID"`
		GenerateIdentityCsr    string `long:"generateIdentityCsr" description:"deviceID"`
	} `group:"Command" namespace:"cmd"`
	Certificate generateCertificate.Configuration `group:"Certificate" namespace:"cert"`
	OutCert     string                            `long:"outCert" default:"cert.pem"`
	OutKey      string                            `long:"outKey" default:"cert.key"`
	OutCsr      string                            `long:"outCsr" default:"req.csr"`
	SignerCert  string                            `long:"signerCert"`
	SignerKey   string                            `long:"signerKey"`
}

func pemBlockForKey(k *ecdsa.PrivateKey) (*pem.Block, error) {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	var cert []byte
	switch {
	case opts.Command.GenerateRootCA:
		cert, err = generateCertificate.GenerateRootCA(opts.Certificate, priv)
		if err != nil {
			log.Fatal(err)
		}
		WriteCertOut(opts, cert)
		WritePrivateKey(opts, priv)
	case opts.Command.GenerateIntermediateCA:
		signerCert, err := security.LoadX509(opts.SignerCert)
		if err != nil {
			log.Fatal(err)
		}
		signerKey, err := security.LoadX509PrivateKey(opts.SignerKey)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = generateCertificate.GenerateIntermediateCA(opts.Certificate, priv, signerCert, signerKey)
		if err != nil {
			log.Fatal(err)
		}
		WriteCertOut(opts, cert)
		WritePrivateKey(opts, priv)
	case opts.Command.GenerateCert:
		signerCert, err := security.LoadX509(opts.SignerCert)
		if err != nil {
			log.Fatal(err)
		}
		signerKey, err := security.LoadX509PrivateKey(opts.SignerKey)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = generateCertificate.GenerateCert(opts.Certificate, priv, signerCert, signerKey)
		if err != nil {
			log.Fatal(err)
		}
		WriteCertOut(opts, cert)
		WritePrivateKey(opts, priv)
	case opts.Command.GenerateIdentity != "":
		signerCert, err := security.LoadX509(opts.SignerCert)
		if err != nil {
			log.Fatal(err)
		}
		signerKey, err := security.LoadX509PrivateKey(opts.SignerKey)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = generateCertificate.GenerateIdentityCert(opts.Certificate, opts.Command.GenerateIdentity, priv, signerCert, signerKey)
		if err != nil {
			log.Fatal(err)
		}
		WriteCertOut(opts, cert)
		WritePrivateKey(opts, priv)
	case opts.Command.GenerateIdentityCsr != "":
		csr, err := generateCertificate.GenerateIdentityCSR(opts.Certificate, opts.Command.GenerateIdentityCsr, priv)
		if err != nil {
			log.Fatal(err)
		}
		WritePrivateKey(opts, priv)
		WriteCsrOut(opts, csr)
	default:
		fmt.Println("invalid command")
		parser.WriteHelp(os.Stdout)
		os.Exit(2)
	}
}

func WriteCertOut(opts Options, cert []byte) {
	certOut, err := os.Create(opts.OutCert)
	if err != nil {
		log.Fatalf("failed to open %v for writing: %s", opts.OutCert, err)
	}
	_, err = certOut.Write(cert)
	if err != nil {
		log.Fatalf("failed to write %v: %s", opts.OutCert, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing %v: %s", opts.OutCert, err)
	}
}

func WriteCsrOut(opts Options, csr []byte) {
	csrOut, err := os.Create(opts.OutCsr)
	if err != nil {
		log.Fatalf("failed to open %v for writing: %s", opts.OutCsr, err)
	}
	_, err = csrOut.Write(csr)
	if err != nil {
		log.Fatalf("failed to write %v: %s", opts.OutCsr, err)
	}
	if err := csrOut.Close(); err != nil {
		log.Fatalf("error closing %v: %s", opts.OutCert, err)
	}
}

func WritePrivateKey(opts Options, priv *ecdsa.PrivateKey) {
	privBlock, err := pemBlockForKey(priv)
	if err != nil {
		log.Fatalf("failed to encode priv key %v for writing: %v", opts.OutKey, err)
	}

	keyOut, err := os.OpenFile(opts.OutKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to open %v for writing: %v", opts.OutKey, err)
	}

	if err := pem.Encode(keyOut, privBlock); err != nil {
		log.Fatalf("failed to write data to %v: %s", opts.OutKey, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing %v: %s", opts.OutKey, err)
	}
}

