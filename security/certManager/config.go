package certManager

import (
	"crypto/tls"
	"fmt"
	"github.com/plgd-dev/kit/security/certManager/server"
	"github.com/plgd-dev/kit/security/certManager/client"
)

// Config provides configuration of a file based Server Certificate manager
type ServerConfig struct {
	Enabled                   	bool 	`yaml:"enabled" json:"enabled" default:"true"`
	CAFile                    	string 	`yaml:"caFile" json:"caFile" description:"file path to the root certificate in PEM format"`
	KeyFile                   	string 	`yaml:"keyFile" json:"keyFile" description:"file name of private key in PEM format"`
	CertFile                  	string 	`yaml:"certFile" json:"certFile" description:"file name of certificate in PEM format"`
	ClientCertificateRequired 	bool   	`yaml:"clientCertificateRequired" json:"clientCertificateRequired" description:"require client ceritificate"`
}

// Config provides configuration of a file based Client Certificate manager
type ClientConfig struct {
	Enabled                   	bool 	`yaml:"enabled" json:"enabled" default:"true"`
	CAFile                    	string 	`yaml:"caFile" json:"caFile" description:"file path to the root certificate in PEM format"`
	KeyFile                   	string 	`yaml:"keyFile" json:"keyFile" description:"file name of private key in PEM format"`
	CertFile                  	string 	`yaml:"certFile" json:"certFile" description:"file name of certificate in PEM format"`
	UseSystemCAPool           	bool   	`yaml:"useSystemCAPool" json:"useSystemCAPool" description:"use system certification pool"`
}

// CertManager represent general CertManager in use
type ServerCertManager interface {
	GetServerTLSConfig() *tls.Config
	Close()
}

type ClientCertManager interface {
	GetClientTLSConfig() *tls.Config
	Close()
}

// NewCertManager create new CertManager
func NewServerCertManager(config ServerConfig) (ServerCertManager, error) {
	if(config.Enabled) {
		return server.NewCertManagerFromConfiguration(config)
	}
	return nil, fmt.Errorf("cannot create cert manager : tls enabled = %v", config.Enabled)
}

func NewClientCertManager(config ClientConfig) (ClientCertManager, error) {
	if(config.Enabled) {
		return client.NewCertManagerFromConfiguration(config)
	}
	return nil, fmt.Errorf("cannot create cert manager : tls enabled = %v", config.Enabled)
}
