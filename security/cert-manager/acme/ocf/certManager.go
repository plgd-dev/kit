package ocf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strconv"
	"time"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/challenge/http01"
	origLego "github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/go-ocf/kit/security"
	"github.com/go-ocf/kit/security/cert-manager/acme"
	"github.com/go-ocf/kit/security/cert-manager/acme/ocf/client"
)

// Config set configuration.
type Config struct {
	acme.Config
	DeviceID string `envconfig:"DEVICE_ID" long:"device_id" description:"DeviceID for OCF Identity Certificate"`
}

type ocfClient struct {
	c *client.Client
}

func (c *ocfClient) Certificate() acme.Certifier {
	return c.c.Certificate()
}

// NewCertManagerFromConfiguration creates certificate manager from config.
func NewCertManagerFromConfiguration(config Config) (*acme.CertManager, error) {
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
	cfg := client.Config{
		Config: origLego.Config{
			CADirURL:   config.CADirURL,
			User:       user,
			HTTPClient: httpClient,
			Certificate: origLego.CertificateConfig{
				KeyType: certcrypto.EC256,
				Timeout: 30 * time.Second,
			},
		},
		DeviceID: config.DeviceID,
	}

	// Create an ACME client and configure use of `http-01` challenge
	acmeClient, err := client.NewClient(cfg)
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
