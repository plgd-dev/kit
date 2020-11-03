package certificateManager

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/plgd-dev/kit/security"
)

// Config provides configuration of a file based Certificate manager
type Config struct {
	CAPool                         string `envconfig:"CA_POOL" long:"ca-pool" description:"file path to the root certificate in PEM format"`
	TLSKeyFileName                 string `envconfig:"CERT_KEY_NAME" long:"cert-key-name" description:"file name of private key in PEM format"`
	DirPath                        string `envconfig:"CERT_DIR_PATH" long:"cert-dir-path" description:"dir path where cert/key pair are saved"`
	TLSCertFileName                string `envconfig:"CERT_NAME" long:"cert-name" description:"file name of certificate in PEM format"`
	DisableVerifyClientCertificate bool   `envconfig:"DISABLE_VERIFY_CLIENT_CERTIFICATE" env:"DISABLE_VERIFY_CLIENT_CERTIFICATE" long:"disable-verify-client-certificate" description:"disable verify client ceritificate"`
	UseSystemCertPool              bool   `envconfig:"USE_SYSTEM_CERTIFICATION_POOL" env:"USE_SYSTEM_CERTIFICATION_POOL"  long:"use-system-certification-pool" description:"use system certifcation pool"`
}

// CertificateManager holds certificates from filesystem watched for changes
type CertificateManager struct {
	mutex                   sync.Mutex
	config                  Config
	tlsKey                  []byte
	tlsCert                 []byte
	tlsKeyPair              tls.Certificate
	certificateAuthorities  []*x509.Certificate
	watcher                 *fsnotify.Watcher
	doneWg                  sync.WaitGroup
	done                    chan struct{}
	verifyClientCertificate tls.ClientAuthType
	newCaCertPoolFunc       func() *x509.CertPool
}

// NewCertificateManager creates a new certificate manager which watches for certs in a filesystem
func NewCertificateManager(config Config) (*CertificateManager, error) {
	var cas []*x509.Certificate
	if config.CAPool != "" {
		certs, err := security.LoadX509(config.CAPool)
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate authorities from '%v': %w", config.CAPool, err)
		}
		cas = certs
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	verifyClientCertificate := tls.RequireAndVerifyClientCert
	if config.DisableVerifyClientCertificate {
		verifyClientCertificate = tls.NoClientCert
	}

	newCaCertPool := func() *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range cas {
			p.AddCert(c)
		}
		return p
	}
	if config.UseSystemCertPool {
		newCaCertPool = func() *x509.CertPool {
			return security.NewDefaultCertPool(cas)
		}
	}

	fileCertMgr := &CertificateManager{
		watcher:                 watcher,
		config:                  config,
		newCaCertPoolFunc:       newCaCertPool,
		verifyClientCertificate: verifyClientCertificate,
		certificateAuthorities:  cas,
	}
	err = fileCertMgr.loadCerts()
	if err != nil {
		return nil, err
	}
	if err := fileCertMgr.watcher.Add(config.DirPath); err != nil {
		return nil, err
	}

	fileCertMgr.done = make(chan struct{})
	fileCertMgr.doneWg.Add(1)

	go fileCertMgr.watchFiles()

	return fileCertMgr, nil
}

// GetCertificateAuthorities returns certificates authorities
func (a *CertificateManager) GetCertificateAuthorities() []*x509.Certificate {
	return a.certificateAuthorities
}

// GetClientTLSConfig returns tls configuration for clients
func (a *CertificateManager) GetClientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:                  a.newCaCertPoolFunc(),
		GetClientCertificate:     a.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}

// GetServerTLSConfig returns tls configuration for servers
func (a *CertificateManager) GetServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:      a.newCaCertPoolFunc(),
		GetCertificate: a.getCertificate2,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     a.verifyClientCertificate,
	}
}

// Close ends watching certificates
func (a *CertificateManager) Close() {
	if a.done != nil {
		_ = a.watcher.Close()
		close(a.done)
		a.doneWg.Wait()
	}
}

func (a *CertificateManager) getCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *CertificateManager) getCertificate2(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *CertificateManager) loadCerts() error {
	if a.config.DirPath != "" && a.config.TLSKeyFileName != "" && a.config.TLSCertFileName != "" {
		keyPath := a.config.DirPath + "/" + a.config.TLSKeyFileName
		tlsKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("cannot load certificate key from '%v': %w", keyPath, err)
		}
		certPath := a.config.DirPath + "/" + a.config.TLSCertFileName
		tlsCert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("cannot load certificate from '%v': %w", certPath, err)
		}
		cert, err := tls.X509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return fmt.Errorf("cannot load certificate pair: %w", err)
		}
		a.setTlsKeyPair(cert)
	}
	return nil
}

func (a *CertificateManager) setTlsKeyPair(cert tls.Certificate) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.tlsKeyPair = cert
}

func (a *CertificateManager) watchFiles() {
	defer a.doneWg.Done()
	for {
		select {
		case <-a.done:
			return
		// watch for events
		case event := <-a.watcher.Events:
			switch event.Op {
			case fsnotify.Create:
				if strings.Contains(event.Name, a.config.TLSKeyFileName) {
					a.tlsKey, _ = ioutil.ReadFile(a.config.DirPath + "/" + a.config.TLSKeyFileName)
				}

				if strings.Contains(event.Name, a.config.TLSCertFileName) {
					a.tlsCert, _ = ioutil.ReadFile(a.config.DirPath + "/" + a.config.TLSCertFileName)
				}

			case fsnotify.Remove:
				if strings.Contains(event.Name, a.config.TLSKeyFileName) {
					a.tlsKey = nil
				}

				if strings.Contains(event.Name, a.config.TLSCertFileName) {
					a.tlsCert = nil
				}
			}

			if a.tlsCert != nil && a.tlsKey != nil {
				cert, err := tls.X509KeyPair(a.tlsCert, a.tlsKey)
				if err == nil {
					a.setTlsKeyPair(cert)
				}
			}
		}
	}
}
