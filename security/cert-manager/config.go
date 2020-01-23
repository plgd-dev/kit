package cert_manager

import (
	"crypto/tls"
	"github.com/go-ocf/kit/security/acme"
)

type Config struct {
	Acme acme.Config
	Type string
}

type CertManager interface {
GetClientTLSConfig() tls.Config
GetServerTLSConfig() tls.Config
}


func ParseConfig(cfg Config) (CertManager, error) {

}