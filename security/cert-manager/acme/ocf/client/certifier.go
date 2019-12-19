package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/go-acme/lego/certificate"
	"github.com/go-ocf/kit/security/cert-manager/acme/client"
	"github.com/go-ocf/kit/security/generateCertificate"
	"golang.org/x/crypto/ocsp"
)

// Constants for OCSP must staple
var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

type certifier struct {
	c          *client.Certifier
	deviceID   string
	privateKey crypto.PrivateKey
}

func getCsr(deviceID string, domains []string, mustStaple bool, privateKey crypto.PrivateKey) (*x509.CertificateRequest, error) {
	template, err := generateCertificate.NewIdentityCSRTemplate(deviceID)
	if err != nil {
		return nil, err
	}
	template.DNSNames = domains

	if mustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    tlsFeatureExtensionOID,
			Value: ocspMustStapleFeature,
		})
	}

	raw, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(raw)
}

// Obtain tries to obtain a single certificate using all domains passed into it.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *certifier) Obtain(request certificate.ObtainRequest) (*certificate.Resource, error) {
	privateKey := request.PrivateKey
	var err error
	var privateKeyBuf []byte
	if privateKey == nil {
		ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKeyBuf, err = x509.MarshalECPrivateKey(ecPrivateKey)
		if err != nil {
			return nil, err
		}
		privateKey = ecPrivateKey
		privateKeyBuf = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBuf})
	}

	csr, err := getCsr(c.deviceID, request.Domains, request.MustStaple, privateKey)
	if err != nil {
		return nil, err
	}
	res, err := c.ObtainForCSR(*csr, request.Bundle)
	if err != nil {
		return nil, err
	}

	res.PrivateKey = privateKeyBuf
	return res, nil
}

// ObtainForCSR tries to obtain a certificate matching the CSR passed into it.
//
// The domains are inferred from the SubjectAltNames, if any.
// The private key for this CSR is not required.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *certifier) ObtainForCSR(csr x509.CertificateRequest, bundle bool) (*certificate.Resource, error) {
	return c.c.ObtainForCSR(csr, bundle)
}

// Revoke takes a PEM encoded certificate or bundle and tries to revoke it at the CA.
func (c *certifier) Revoke(cert []byte) error {
	return c.c.Revoke(cert)
}

// Renew takes a Resource and tries to renew the certificate.
//
// If the renewal process succeeds, the new certificate will ge returned in a new CertResource.
// Please be aware that this function will return a new certificate in ANY case that is not an error.
// If the server does not provide us with a new cert on a GET request to the CertURL
// this function will start a new-cert flow where a new certificate gets generated.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// For private key reuse the PrivateKey property of the passed in Resource should be non-nil.
func (c *certifier) Renew(certRes certificate.Resource, bundle, mustStaple bool) (*certificate.Resource, error) {
	return c.c.Renew(certRes, bundle, mustStaple)
}

// GetOCSP takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any.
//
// The returned []byte can be passed directly into the OCSPStaple property of a tls.Certificate.
// If the bundle only contains the issued certificate,
// this function will try to get the issuer certificate from the IssuingCertificateURL in the certificate.
//
// If the []byte and/or ocsp.Response return values are nil, the OCSP status may be assumed OCSPUnknown.
func (c *certifier) GetOCSP(bundle []byte) ([]byte, *ocsp.Response, error) {
	return c.c.GetOCSP(bundle)
}

// Get attempts to fetch the certificate at the supplied URL.
// The URL is the same as what would normally be supplied at the Resource's CertURL.
//
// The returned Resource will not have the PrivateKey and CSR fields populated as these will not be available.
//
// If bundle is true, the Certificate field in the returned Resource includes the issuer certificate.
func (c *certifier) Get(url string, bundle bool) (*certificate.Resource, error) {
	return c.c.Get(url, bundle)
}
