package certManager

import (
	"crypto/tls"
	"fmt"
)

// Config provides configuration of a file based Certificate manager
type Config struct {
	Enabled                   	bool 	`yaml:"enabled" json:"enabled" default:"true"`
	CAFile                    	string 	`yaml:"caFile" json:"caFile" description:"file path to the root certificate in PEM format"`
	KeyFile                   	string 	`yaml:"keyFile" json:"keyFile" description:"file name of private key in PEM format"`
	CertFile                  	string 	`yaml:"certFile" json:"certFile" description:"file name of certificate in PEM format"`
	ClientCertificateRequired 	bool   	`yaml:"clientCertificateRequired" json:"clientCertificateRequired" description:"require client ceritificate"`
	UseSystemCAPool           	bool   	`yaml:"useSystemCAPool" json:"useSystemCAPool" description:"use system certification pool"`
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
