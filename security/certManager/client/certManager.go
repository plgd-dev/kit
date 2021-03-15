package client

import (
	"crypto/tls"
	"fmt"

	"github.com/plgd-dev/kit/security/certManager/general"
	"go.uber.org/zap"
)

// Config provides configuration of a file based Server Certificate manager
type Config struct {
	CAFile          string `yaml:"caFile" json:"caFile" description:"file path to the root certificate in PEM format"`
	KeyFile         string `yaml:"keyFile" json:"keyFile" description:"file name of private key in PEM format"`
	CertFile        string `yaml:"certFile" json:"certFile" description:"file name of certificate in PEM format"`
	UseSystemCAPool bool   `yaml:"useSystemCAPool" json:"useSystemCAPool" description:"use system certification pool"`
}

func (c Config) Validate() error {
	if c.CAFile == "" && !c.UseSystemCAPool {
		return fmt.Errorf("invalid caFile")
	}
	if c.CertFile == "" {
		return fmt.Errorf("invalid certFile")
	}
	if c.KeyFile == "" {
		return fmt.Errorf("invalid keyFile")
	}
	return nil
}

func (c *Config) SetDefaults() {
}

// CertManager holds certificates from filesystem watched for changes
type CertManager struct {
	c *general.CertManager
}

// GetTLSConfig returns tls configuration for clients
func (c *CertManager) GetTLSConfig() *tls.Config {
	return c.c.GetClientTLSConfig()
}

// Close ends watching certificates
func (c *CertManager) Close() {
	c.c.Close()
}

// New creates a new certificate manager which watches for certs in a filesystem
func New(config Config, logger *zap.Logger) (*CertManager, error) {
	c, err := general.New(general.Config{
		CAFile:                    config.CAFile,
		KeyFile:                   config.KeyFile,
		CertFile:                  config.CertFile,
		ClientCertificateRequired: false,
		UseSystemCAPool:           config.UseSystemCAPool,
	}, logger)
	if err != nil {
		return nil, err
	}
	return &CertManager{
		c: c,
	}, nil
}
