package certManager

import (
	"crypto/tls"
	"fmt"
	"github.com/plgd-dev/kit/security/certManager/server"
	"github.com/plgd-dev/kit/security/certManager/client"
)


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
