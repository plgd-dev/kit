package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	host             = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFor         = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	generateCA       = flag.Bool("generateCa", false, "whether this cert should be its own Certificate Authority")
	ecdsaCurve       = flag.String("ecdsa-curve", "P256", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	generateIdentity = flag.String("generateIdentity", "", "uuid of device")
	caKey            = flag.String("caKey", "", "caKey")
	caCert           = flag.String("caCert", "", "caPem")
)

var ekuOcfId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44924, 1, 6}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func main() {
	flag.Parse()

	if *generateIdentity != "" && len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}
	if *generateIdentity != "" && len(*caKey) == 0 {
		log.Fatalf("Missing required --caKey parameter")
	}
	if *generateIdentity != "" && len(*caCert) == 0 {
		log.Fatalf("Missing required --caCert parameter")
	}
	if !*generateCA && *generateIdentity == "" {
		log.Fatalf("Missing required --generateCa or --generateIdentity  parameter")
	}

	var priv interface{}
	var err error

	switch *ecdsaCurve {
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", *ecdsaCurve)
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(*validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test ORG"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}

	}

	var parent *x509.Certificate
	var privateKeyOfSigner interface{}
	certFilename := "cert.pem"
	keyFilename := "key.pem"

	if *generateIdentity != "" {
		template.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		template.Subject.CommonName = fmt.Sprintf("uuid:%v", *generateIdentity)
		template.UnknownExtKeyUsage = append(template.UnknownExtKeyUsage, ekuOcfId)
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)

		certPEMBlock, err := ioutil.ReadFile(*caCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot load ca certificate for signing: %v", err)
			os.Exit(1)
		}
		keyPEMBlock, err := ioutil.ReadFile(*caKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot load ca key for signing: %v", err)
			os.Exit(1)
		}
		certBlock, _ := pem.Decode(certPEMBlock)
		if certBlock == nil {
			fmt.Fprintf(os.Stderr, "cannot decode pem from ca pem for signing")
			os.Exit(1)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot parse ca cert for signing: %v", err)
			os.Exit(1)
		}
		keyBlock, _ := pem.Decode(keyPEMBlock)
		if keyBlock == nil {
			fmt.Fprintf(os.Stderr, "cannot decode pem from ca pem for signing")
			os.Exit(1)
		}
		key, e := x509.ParseECPrivateKey(keyBlock.Bytes)
		if e != nil {
			fmt.Fprintf(os.Stderr, "cannot parse ca key for signing: %v", err)
			os.Exit(1)
		}

		parent = cert
		privateKeyOfSigner = key
	} else if *generateCA {
		certFilename = "cacert.pem"
		keyFilename = "cakey.pem"
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		parent = &template
		privateKeyOfSigner = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, publicKey(priv), privateKeyOfSigner)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(certFilename)
	if err != nil {
		log.Fatalf("failed to open %v for writing: %s", certFilename, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to %v: %s", certFilename, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing %v: %s", certFilename, err)
	}

	log.Printf("wrote %v\n", certFilename)

	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to open %v for writing: %v", keyFilename, err)
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		log.Fatalf("failed to write data to %v: %s", keyFilename, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing %v: %s", keyFilename, err)
	}
	log.Printf("wrote %v\n", keyFilename)
}
