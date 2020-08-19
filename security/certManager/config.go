package certManager

import (
	"crypto/tls"
	"fmt"

	"github.com/plgd-dev/kit/security/certManager/acme"
	"github.com/plgd-dev/kit/security/certManager/acme/ocf"
	"github.com/plgd-dev/kit/security/certManager/file"
)

// AcmeType define acme type certificate manager
const AcmeType = "acme"

// FileType define static file type certificate manager
const FileType = "file"

// Config provides configuration of a file/acme based Certificate manager
type Config struct {
	Type string      `envconfig:"TYPE" default:"acme"`
	Acme acme.Config `envconfig:"ACME"`
	File file.Config `envconfig:"FILE"`
}

// OcfConfig provides configuration of a file/acme based Certificate manager
type OcfConfig struct {
	Type string      `envconfig:"TYPE" default:"acme"`
	Acme ocf.Config  `envconfig:"ACME"`
	File file.Config `envconfig:"FILE"`
}

// CertManager represent general CertManager in use
type CertManager interface {
	GetClientTLSConfig() *tls.Config
	GetServerTLSConfig() *tls.Config
	Close()
}

// NewCertManager create new CertManager
func NewCertManager(config Config) (CertManager, error) {
	if config.Type == AcmeType {
		return acme.NewCertManagerFromConfiguration(config.Acme)
	} else if config.Type == FileType {
		return file.NewCertManagerFromConfiguration(config.File)
	}
	return nil, fmt.Errorf("unable to create cert manager. Invalid tls config type: %s", config.Type)
}

// NewOcfCertManager create new CertManager
func NewOcfCertManager(config OcfConfig) (CertManager, error) {
	if config.Type == AcmeType {
		return ocf.NewAcmeCertManagerFromConfiguration(config.Acme)
	} else if config.Type == FileType {
		return file.NewCertManagerFromConfiguration(config.File)
	}
	return nil, fmt.Errorf("unable to create cert manager. Invalid tls config type: %s", config.Type)
}
