package certManager

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ocf/kit/security/acme"
	"github.com/go-ocf/kit/security/certManager/file"
)

const acmeType = "acme"
const fileType = "file"

// Config provides configuration of a file based Certificate manager
type Config struct {
	Type string      `envconfig:"TYPE" default:"acme"`
	Acme acme.Config `envconfig:"ACME"`
	File file.Config `envconfig:"FILE"`
}

// CertManager represent general CertManager in use
type CertManager interface {
	GetClientTLSConfig() tls.Config
	GetServerTLSConfig() tls.Config
	Close()
}

// NewCertManager create new CertManager
func NewCertManager(config Config) (CertManager, error) {
	if config.Type == acmeType {
		return acme.NewCertManagerFromConfiguration(config.Acme)
	} else if config.Type == fileType {
		return file.NewFileCertManagerFromConfiguration(config.File)
	}
	return nil, fmt.Errorf("unable to create cert manager. Invalid tls config type: %s", config.Type)
}

