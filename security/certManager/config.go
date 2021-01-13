package certManager

import (
	"crypto/tls"
	"fmt"
)

// Config provides configuration of a file based Certificate manager
type Config struct {
	Enabled                   	bool 	`envconfig:"ENABLED" json:"enabled" default:"true"`
	CAFile                    	string 	`envconfig:"CA_POOL" json:"ca-file" description:"file path to the root certificate in PEM format"`
	KeyFile                   	string 	`envconfig:"CERT_KEY_NAME" json:"key-file" description:"file name of private key in PEM format"`
	DirPath                   	string 	`envconfig:"CERT_DIR_PATH" json:"dir-path" description:"dir path where cert/key pair are saved"`
	CertFile                  	string 	`envconfig:"CERT_NAME" json:"cert-file" description:"file name of certificate in PEM format"`
	ClientCertificateRequired 	bool   	`envconfig:"CLIENT_CERTIFICATE_REQUIRED" json:"client-certificate-required" description:"require client ceritificate"`
	UseSystemCAPool           	bool   	`envconfig:"USE_SYSTEM_CA_POOL" json:"use-system-ca-pool" description:"use system certifcation pool"`
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
