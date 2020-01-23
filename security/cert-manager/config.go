package cert_manager

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ocf/kit/security/acme"
	"github.com/go-ocf/kit/security/cert-manager/file"
)

const AcmeType = "acme"
const FileType = "file"

type Config struct {
	Type string      `envconfig:"TYPE" default:"acme"`
	Acme acme.Config `envconfig:"ACME"`
	File file.Config `envconfig:"FILE"`
}

type CertManager interface {
	GetClientTLSConfig() tls.Config
	GetServerTLSConfig() tls.Config
	Close()
}

func NewCertManager(config Config) (CertManager, error) {
	if config.Type == AcmeType {
		return acme.NewCertManagerFromConfiguration(config.Acme)
	} else if config.Type == FileType {
		return file.NewFileCertManagerFromConfiguration(config.File)
	}
	return nil, fmt.Errorf("unable to create cert manager. Invalid tls config type: %s", config.Type)
}

