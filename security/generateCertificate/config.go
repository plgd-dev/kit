package generateCertificate

import (
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
	MaxPathLen         int           `long:"maxPathLen" default:"-1"  description:"int, -1 means unlimited"`
	ValidFor           time.Duration `long:"validFor" default:"8760h" description:"duration, format in NUMh"`
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

func (cfg Configuration) ToExtensionKeyUsages() ([]asn1.ObjectIdentifier, error) {
	var ekus []asn1.ObjectIdentifier
	for _, e := range cfg.ExtensionKeyUsages {
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
