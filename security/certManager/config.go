package certManager

import (
	"crypto/tls"
	tls2 "github.com/plgd-dev/kit/security/certManager/tls"
)

// Config provides configuration of a file/acme based Certificate manager
type Config struct {
	tls tls2.Config		`envconfig:"TLS"`
}

// OcfConfig provides configuration of a file/acme based Certificate manager
type OcfConfig struct {
	tls tls2.Config		`envconfig:"TLS"`
}

// CertManager represent general CertManager in use
type CertManager interface {
	GetClientTLSConfig() *tls.Config
	GetServerTLSConfig() *tls.Config
	Close()
}

// NewCertManager create new CertManager
func NewCertManager(config Config) (CertManager, error) {

	return tls2.NewCertManagerFromConfiguration(config.tls)
}

// NewOcfCertManager create new CertManager
func NewOcfCertManager(config OcfConfig) (CertManager, error) {

	return tls2.NewCertManagerFromConfiguration(config.tls)
}
