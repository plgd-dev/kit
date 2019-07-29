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

func (cfg Configuration) X509KeyUsages() (x509.KeyUsage, error) {
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
			return 0, fmt.Errorf("invalid key usage %v", k)
		}
	}
	return ku, nil
}

func (cfg Configuration) AsnKeyUsages() (asn1.BitString, error) {
	ku, err := cfg.X509KeyUsages()
	if err != nil {
		return asn1.BitString{}, err
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

func (cfg Configuration) X509ExtKeyUsages() ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	unknownEkus := make([]asn1.ObjectIdentifier, 0, 4)
	ekus := make([]x509.ExtKeyUsage, 0, 4)
	for _, e := range cfg.ExtensionKeyUsages {
		switch e {
		case "server":
			ekus = append(ekus, x509.ExtKeyUsageServerAuth)
		case "client":
			ekus = append(ekus, x509.ExtKeyUsageClientAuth)
		case "":
		default:
			var eku asn1.ObjectIdentifier
			oidStr := strings.Split(e, ".")
			for _, v := range oidStr {
				i, err := strconv.Atoi(v)
				if err != nil {
					return nil, nil, err
				}
				eku = append(eku, i)
			}
			if len(eku) > 0 {
				unknownEkus = append(unknownEkus, eku)
			}
		}
	}
	if len(ekus) == 0 {
		ekus = nil
	}
	if len(unknownEkus) == 0 {
		unknownEkus = nil
	}
	return ekus, unknownEkus, nil
}

// copied from https://golang.org/src/crypto/x509/x509.go
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func OidFromExtKeyUsage(eku x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

func (cfg Configuration) AsnExtensionKeyUsages() ([]asn1.ObjectIdentifier, error) {
	ekus, unknownEkus, err := cfg.X509ExtKeyUsages()
	if err != nil {
		return nil, err
	}
	res := make([]asn1.ObjectIdentifier, 0, len(ekus)+len(unknownEkus))
	for _, e := range ekus {
		v, ok := OidFromExtKeyUsage(e)
		if !ok {
			return nil, fmt.Errorf("cannot convert x509.KeyUsage %v to oid: oid representation not found", e)
		}
		res = append(res, v)
	}
	res = append(res, unknownEkus...)
	return res, nil
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
