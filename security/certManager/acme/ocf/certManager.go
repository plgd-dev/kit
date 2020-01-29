package ocf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/go-ocf/kit/security/certManager"
	"github.com/go-ocf/kit/security/certManager/acme"
	"github.com/go-ocf/kit/security/certManager/file"

	client2 "github.com/go-ocf/kit/security/certManager/acme/ocf/client"
	"strconv"
	"time"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/challenge/http01"
	origLego "github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/go-ocf/kit/security"
)

// Config set configuration.
type Config struct {
	certManager.Config
	DeviceID string `envconfig:"ACME_DEVICE_ID" env:"ACME_DEVICE_ID" long:"device_id" description:"DeviceID for OCF Identity Certificate"`
}

// NewOcfCertManager create new CertManager
func NewOcfCertManager(config Config) (certManager.CertManager, error) {
	if config.Type == certManager.FileType {
		return file.NewCertManagerFromConfiguration(config.File)
	} else if config.Type == certManager.AcmeType {
		return newAcmeCertManagerFromConfiguration(config.Acme, config.DeviceID)
	}
	return nil, fmt.Errorf("unable to create ocf cert manager. Invalid tls config type: %s", config.Type)
}


type ocfClient struct {
	c *client2.Client
}

func (c *ocfClient) Certificate() acme.Certifier {
	return c.c.Certificate()
}

// newAcmeCertManagerFromConfiguration creates certificate manager from config.
func newAcmeCertManagerFromConfiguration(config acme.Config, deviceID string) (certManager.CertManager, error) {
	var cas []*x509.Certificate
	if config.CAPool != "" {
		certs, err := security.LoadX509(config.CAPool)
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate authorities from '%v': %w", config.CAPool, err)
		}
		cas = certs
	}
	if config.ChallengeListenPort == 0 {
		return nil, fmt.Errorf("invalid ChallengeListenPort")
	}

	// Create a new ACME user with a new key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	user := acme.NewUser(config.Email, key)

	// Get an HTTPS client configured to trust our root certificate.
	httpClient, err := acme.GetHTTPSClient(cas)
	if err != nil {
		return nil, err
	}

	// Create a configuration using our HTTPS client, ACME server, user details.
	cfg := client2.Config{
		Config: origLego.Config{
			CADirURL:   config.CADirURL,
			User:       user,
			HTTPClient: httpClient,
			Certificate: origLego.CertificateConfig{
				KeyType: certcrypto.EC256,
				Timeout: 30 * time.Second,
			},
		},
		DeviceID: deviceID,
	}

	// Create an ACME client and configure use of `http-01` challenge
	acmeClient, err := client2.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	err = acmeClient.Challenge().SetHTTP01Provider(http01.NewProviderServer("", strconv.Itoa(int(config.ChallengeListenPort))))
	if err != nil {
		return nil, err
	}

	// Register our ACME user
	registration, err := acmeClient.Registration().Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	user.SetRegistration(registration)

	return acme.NewCertManager(cas, config.Domains, config.TickFrequency, &ocfClient{acmeClient})
}
