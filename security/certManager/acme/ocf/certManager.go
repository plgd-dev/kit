package ocf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/go-ocf/kit/security/certManager/acme"
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
	CAPool              string        `envconfig:"CA_POOL" env:"CA_POOL" long:"ca" description:"file path to the root certificate in PEM format"`
	CADirURL            string        `envconfig:"DIRECTORY_URL" env:"DIRECTORY_URL" long:"acme-directory-url" description:"the ACME directory URL for your ACME server"`
	Domains             []string      `envconfig:"DOMAINS" env:"DOMAINS" long:"domains" description:"the domain's names for which we'll be getting a certificate"`
	Email               string        `envconfig:"REGISTRATION_EMAIL" env:"REGISTRATION_EMAIL" long:"email" description:"the email address to use during ACME registration"`
	TickFrequency       time.Duration `envconfig:"TICK_FREQUENCY" env:"TICK_FREQUENCY" long:"tick-frequency" description:"how frequently we should check whether our cert needs renewal" default:"15s"`
	ChallengeListenPort uint16        `envconfig:"CHALLENGE_LISTEN_PORT" env:"CHALLENGE_LISTEN_PORT" long:"challenge-listen-port" default:"80" description:"listen port to accept challenge requests from acme server"`
	DeviceID            string        `envconfig:"DEVICE_ID" env:"DEVICE_ID" long:"device_id" description:"DeviceID for OCF Identity Certificate"`
}

type ocfClient struct {
	c *client2.Client
}

func (c *ocfClient) Certificate() acme.Certifier {
	return c.c.Certificate()
}

// NewAcmeCertManagerFromConfiguration creates certificate manager from config.
func NewAcmeCertManagerFromConfiguration(config Config) (*acme.CertManager, error) {
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
		DeviceID: config.DeviceID,
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
