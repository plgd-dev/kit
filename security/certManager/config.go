package certManager

import (
	"crypto/tls"
	"fmt"
)

// Config provides configuration of a file based Certificate manager
type Config struct {
	Enabled                   	bool 	`yaml:"enabled" json:"enabled" default:"true"`
	CAFile                    	string 	`yaml:"ca-file" json:"ca-file" description:"file path to the root certificate in PEM format"`
	KeyFile                   	string 	`yaml:"key-file" json:"key-file" description:"file name of private key in PEM format"`
	CertFile                  	string 	`yaml:"cert-file" json:"cert-file" description:"file name of certificate in PEM format"`
	ClientCertificateRequired 	bool   	`yaml:"client-certificate-required" json:"client-certificate-required" description:"require client ceritificate"`
	UseSystemCAPool           	bool   	`yaml:"use-system-ca-pool" json:"use-system-ca-pool" description:"use system certifcation pool"`
}

// CertManager represent general CertManager in use
type CertManager interface {
	GetClientTLSConfig() *tls.Config
	GetServerTLSConfig() *tls.Config
	Close()
}

// NewCertManager create new CertManager
func NewCertManager(config Config) (CertManager, error) {
	if(config.Enabled) {
		return NewCertManagerFromConfiguration(config)
	}
	return nil, fmt.Errorf("cannot create cert manager : tls enabled = %v", config.Enabled)
}

// NewOcfCertManager create new CertManager
func NewOcfCertManager(config Config) (CertManager, error) {
	if(config.Enabled) {
		return NewCertManagerFromConfiguration(config)
	}
	return nil, fmt.Errorf("cannot create cert manager : tls enabled = %v", config.Enabled)
}
