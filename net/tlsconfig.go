package net

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-ocf/kit/log"
)

// TLSConfig set configuration.
type TLSConfig struct {
	Certificate    string `envconfig:"TLS_CERTIFICATE"`
	CertificateKey string `envconfig:"TLS_CERTIFICATE_KEY"`
	CAPool         string `envconfig:"TLS_CA_POOL"`
}

// VerifyCertificateFunc verify EKU, revocations and other staff of certificate.
type VerifyCertificateFunc func(conn net.Conn, certificate *x509.Certificate) error

// SetTLSConfig setup tls.Config that provides verification certificate with connection.
func SetTLSConfig(config TLSConfig, verifyCertificate VerifyCertificateFunc) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(config.Certificate, config.CertificateKey)
	if err != nil {
		return nil, err
	}

	caRootPool := x509.NewCertPool()
	caIntermediatesPool := x509.NewCertPool()

	err = filepath.Walk(config.CAPool, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}

		// check if it is a regular file (not dir)
		if info.Mode().IsRegular() {
			certPEMBlock, err := ioutil.ReadFile(path)
			if err != nil {
				log.Warnf("cannot read file '%v': %v", path, err)
				return nil
			}
			certDERBlock, _ := pem.Decode(certPEMBlock)
			if certDERBlock == nil {
				log.Warnf("cannot decode der block '%v'", path)
				return nil
			}
			if certDERBlock.Type != "CERTIFICATE" {
				log.Warnf("DER block is not certificate '%v'", path)
				return nil
			}
			caCert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				log.Warnf("cannot parse certificate '%v': %v", path, err)
				return nil
			}
			if bytes.Compare(caCert.RawIssuer, caCert.RawSubject) == 0 && caCert.IsCA {
				log.Infof("adding root certificate '%v'", path)
				caRootPool.AddCert(caCert)
			} else if caCert.IsCA {
				log.Infof("adding intermediate certificate '%v'", path)
				caIntermediatesPool.AddCert(caCert)
			} else {
				log.Warnf("ignoring certificate '%v'", path)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if len(caRootPool.Subjects()) == 0 {
		return nil, fmt.Errorf("CA Root pool is empty")
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			//https://github.com/golang/go/issues/29895
			m := tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequireAnyClientCert,
			}
			m.VerifyPeerCertificate = newVerifyPeerCert(caIntermediatesPool, caRootPool, info.Conn, verifyCertificate)
			return &m, nil
		},
	}

	return &tlsConfig, nil
}

func newVerifyPeerCert(intermediates *x509.CertPool, roots *x509.CertPool, conn net.Conn, verifyCertificate VerifyCertificateFunc) func(rawCerts [][]byte, verifyChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifyChains [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return err
			}

			_, err = cert.Verify(x509.VerifyOptions{
				Intermediates: intermediates,
				Roots:         roots,
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err != nil {
				return err
			}
			err = verifyCertificate(conn, cert)
			if err != nil {
				return err
			}
		}
		return nil
	}
}
