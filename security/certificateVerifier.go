package security

import (
	"crypto/x509"
	"fmt"
)

// VerifyClientCertificate verifies client certificate
func VerifyClientCertificate(certificate *x509.Certificate) error {
	// verify EKU
	for _, eku := range certificate.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return nil
		}
	}
	return fmt.Errorf("invalid certificate: ExtKeyUsageClientAuth not found")
}

// VerifyServerCertificate verifies server certificate
func VerifyServerCertificate(certificate *x509.Certificate) error {
	// verify EKU
	for _, eku := range certificate.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return nil
		}
	}
	return fmt.Errorf("invalid certificate: ExtKeyUsageServerAuth not found")
}
