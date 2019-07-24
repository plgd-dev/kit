package generateCertificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Configuration struct {
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
	BasicConstraints struct {
		Ignore     bool `long:"ignore"  description:"bool, don't set basic constraints"`
		MaxPathLen int  `long:"maxPathLen" default:"-1"  description:"int, -1 means unlimited"`
	} `group:"Basic Constraints" namespace:"basicConstraints"`
	ValidFor           time.Duration `long:"validFor" default:"8760h" description:"duration, format in NUMh"`
	KeyUsages          []string      `long:"ku" default:"digitalSignature" default:"keyAgreement" description:"to set more values repeat option with parameter"`
	ExtensionKeyUsages []string      `long:"eku" default:"client" default:"server" description:"to set more values repeat option with parameter"`
}

func (cfg Configuration) ToPkixName() pkix.Name {
	return pkix.Name{
		Country:            cfg.Subject.Country,
		Organization:       cfg.Subject.Organization,
		OrganizationalUnit: cfg.Subject.OrganizationalUnit,
		CommonName:         cfg.Subject.CommonName,
		Locality:           cfg.Subject.Locality,
		Province:           cfg.Subject.PostalCode,
	}
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

func (cfg Configuration) ToKeyUsages() (asn1.BitString, error) {
	var ku x509.KeyUsage
	for _, k := range cfg.KeyUsages {
		switch k {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "contentCommitment":
			ku |= x509.KeyUsageContentCommitment
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyAgreement":
			ku |= x509.KeyUsageKeyAgreement
		case "certSign":
			ku |= x509.KeyUsageCertSign
		case "crlSign":
			ku |= x509.KeyUsageCRLSign
		case "encipherOnly":
			ku |= x509.KeyUsageEncipherOnly
		case "decipherOnly":
			ku |= x509.KeyUsageDecipherOnly
		case "":
		default:
			return asn1.BitString{}, fmt.Errorf("invalid key usage %v", k)
		}
	}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	return asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)}, nil
}

func (cfg Configuration) ToExtensionKeyUsages() ([]asn1.ObjectIdentifier, error) {
	var ekus []asn1.ObjectIdentifier
	for _, e := range cfg.ExtensionKeyUsages {
		switch e {
		case "server":
			ekus = append(ekus, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		case "client":
			ekus = append(ekus, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
		case "":
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

func (cfg Configuration) ToIPAddresses() ([]net.IP, error) {
	var ips []net.IP
	for _, ip := range cfg.SubjectAlternativeName.IPAddresses {
		v := net.ParseIP(ip)
		if v == nil {
			return nil, fmt.Errorf("invalid IP address: %v", ip)
		}
		ips = append(ips, v)
	}
	return ips, nil
}
