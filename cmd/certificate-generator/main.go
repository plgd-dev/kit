package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ocf/kit/security"
	flags "github.com/jessevdk/go-flags"
)

type Options struct {
	Command struct {
		GenerateRootCA         bool   `long:"generateRootCA"`
		GenerateIntermediateCA bool   `long:"generateIntermediateCA"`
		GenerateCert           bool   `long:"generateCertificate"`
		GenerateIdentity       string `long:"generateIdentityCertificate" description:"string{\"deviceID\"}"`
	} `group:"Command" namespace:"cmd"`
	Certificate struct {
		Subject struct {
			Country            []string `long:"c" description:"to set more values repeat option with parameter"`
			Organization       []string `long:"o" description:"to set more values repeat option with parameter"`
			OrganizationalUnit []string `long:"ou" description:"to set more values repeat option with parameter"`
			Locality           []string `long:"l" description:"to set more values repeat option with parameter"`
			CommonName         string   `long:"cn"`
			Province           []string `long:"p" description:"to set more values repeat option with parameter"`
			StreetAddress      []string `long:"sa" description:"to set more values repeat option with parameter"`
			PostalCode         []string `long:"pc" description:"to set more values repeat option with parameter"`
			SerialNumber       string   `long:"sn"`
		} `group:"Subject" namespace:"subject"`
		SubjectAlternativeName struct {
			DNSNames    []string `long:"domain" description:"to set more values repeat option with parameter"`
			IPAddresses []string `long:"ip" description:"to set more values repeat option with parameter"`
		} `group:"Subject Alternative Name" namespace:"san"`
		MaxPathLen         int           `long:"maxPathLen" default:"-1"  description:"int"`
		ValidFor           time.Duration `long:"validFor" default:"8760h"`
		ExtensionKeyUsages []string      `long:"eku" default:"client" default:"server" description:"to set more values repeat option with parameter"`
	} `group:"Certificate" namespace:"cert"`
	OutCert    string `long:"outCert" default:"cert.pem"`
	OutKey     string `long:"outKey" default:"cert.key"`
	SignerCert string `long:"signerCert"`
	SignerKey  string `long:"signerKey"`
}

func (opts Options) ToPkixName() pkix.Name {
	return pkix.Name{
		Country:            opts.Certificate.Subject.Country,
		Organization:       opts.Certificate.Subject.Organization,
		OrganizationalUnit: opts.Certificate.Subject.OrganizationalUnit,
		CommonName:         opts.Certificate.Subject.CommonName,
		Locality:           opts.Certificate.Subject.Locality,
		Province:           opts.Certificate.Subject.PostalCode,
	}
}

func pemBlockForKey(k *ecdsa.PrivateKey) (*pem.Block, error) {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
}

func (opts Options) ToExtensionKeyUsages() ([]asn1.ObjectIdentifier, error) {
	var ekus []asn1.ObjectIdentifier
	for _, e := range opts.Certificate.ExtensionKeyUsages {
		switch e {
		case "server":
			ekus = append(ekus, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		case "client":
			ekus = append(ekus, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
		default:
			var eku asn1.ObjectIdentifier
			oidStr := strings.Split(e, ".")
			for _, v := range oidStr {
				i, err := strconv.Atoi(v)
				if err != nil {
					return nil, err
				}
				eku = append(eku, i)
			}
			if len(eku) > 0 {
				ekus = append(ekus, eku)
			}
		}
	}
	return ekus, nil
}

func (opts Options) ToIPAddresses() ([]net.IP, error) {
	var ips []net.IP
	for _, ip := range opts.Certificate.SubjectAlternativeName.IPAddresses {
		v := net.ParseIP(ip)
		if v == nil {
			return nil, fmt.Errorf("invalid IP address: %v", ip)
		}
		ips = append(ips, v)
	}
	return ips, nil
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	if err != nil {
		fmt.Println(err)
		parser.WriteHelp(os.Stdout)
		os.Exit(2)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	var cert []byte
	switch {
	case opts.Command.GenerateRootCA:
		cert, err = generateRootCA(opts, priv)
		if err != nil {
			log.Fatal(err)
		}
	case opts.Command.GenerateIntermediateCA:
		signerCert, err := security.LoadX509(opts.SignerCert)
		if err != nil {
			log.Fatal(err)
		}
		signerKey, err := security.LoadX509PrivateKey(opts.SignerKey)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = generateIntermediateCA(opts, priv, signerCert, signerKey)
		if err != nil {
			log.Fatal(err)
		}
	case opts.Command.GenerateCert:
		signerCert, err := security.LoadX509(opts.SignerCert)
		if err != nil {
			log.Fatal(err)
		}
		signerKey, err := security.LoadX509PrivateKey(opts.SignerKey)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = generateCert(opts, priv, signerCert, signerKey)
		if err != nil {
			log.Fatal(err)
		}
	case opts.Command.GenerateIdentity != "":
		signerCert, err := security.LoadX509(opts.SignerCert)
		if err != nil {
			log.Fatal(err)
		}
		signerKey, err := security.LoadX509PrivateKey(opts.SignerKey)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = generateIdentityCert(opts, priv, signerCert, signerKey)
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Println("invalid command")
		parser.WriteHelp(os.Stdout)
		os.Exit(2)
	}

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
