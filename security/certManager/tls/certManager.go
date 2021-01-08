package tls

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
	enabled                   bool 	 `envconfig:"ENABLED" long:"tls-enabled" `
	caFile                    string `envconfig:"CA_POOL" long:"tls-file-ca-pool" description:"file path to the root certificate in PEM format"`
	keyFile                   string `envconfig:"CERT_KEY_NAME" long:"tls-file-cert-key-name" description:"file name of private key in PEM format"`
	dirPath                   string `envconfig:"CERT_DIR_PATH" long:"tls-file-cert-dir-path" description:"dir path where cert/key pair are saved"`
	certFile                  string `envconfig:"CERT_NAME" long:"tls-file-cert-name" description:"file name of certificate in PEM format"`
	clientCertificateRequired bool   `envconfig:"DISABLE_VERIFY_CLIENT_CERTIFICATE" env:"DISABLE_VERIFY_CLIENT_CERTIFICATE" long:"disable-verify-client-certificate" description:"disable verify client ceritificate"`
	useSystemCAPool           bool   `envconfig:"USE_SYSTEM_CERTIFICATION_POOL" env:"USE_SYSTEM_CERTIFICATION_POOL"  long:"use-system-certification-pool" description:"use system certifcation pool"`
}

// CertManager holds certificates from filesystem watched for changes
type CertManager struct {
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

// NewCertManagerFromConfiguration creates a new certificate manager which watches for certs in a filesystem
func NewCertManagerFromConfiguration(config Config) (*CertManager, error) {
	var cas []*x509.Certificate
	if config.caFile != "" {
		certs, err := security.LoadX509(config.caFile)
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate authorities from '%v': %w", config.caFile, err)
		}
		cas = certs
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	verifyClientCertificate := tls.RequireAndVerifyClientCert
	if !config.clientCertificateRequired {
		verifyClientCertificate = tls.NoClientCert
	}

	newCaCertPool := func() *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range cas {
			p.AddCert(c)
		}
		return p
	}
	if config.useSystemCAPool {
		newCaCertPool = func() *x509.CertPool {
			return security.NewDefaultCertPool(cas)
		}
	}

	fileCertMgr := &CertManager{
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
	if err := fileCertMgr.watcher.Add(config.dirPath); err != nil {
		return nil, err
	}

	fileCertMgr.done = make(chan struct{})
	fileCertMgr.doneWg.Add(1)

	go fileCertMgr.watchFiles()

	return fileCertMgr, nil
}

// GetCertificateAuthorities returns certificates authorities
func (a *CertManager) GetCertificateAuthorities() []*x509.Certificate {
	return a.certificateAuthorities
}

// GetClientTLSConfig returns tls configuration for clients
func (a *CertManager) GetClientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:                  a.newCaCertPoolFunc(),
		GetClientCertificate:     a.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}

// GetServerTLSConfig returns tls configuration for servers
func (a *CertManager) GetServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:      a.newCaCertPoolFunc(),
		GetCertificate: a.getCertificate2,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     a.verifyClientCertificate,
	}
}

// Close ends watching certificates
func (a *CertManager) Close() {
	if a.done != nil {
		_ = a.watcher.Close()
		close(a.done)
		a.doneWg.Wait()
	}
}

func (a *CertManager) getCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *CertManager) getCertificate2(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *CertManager) loadCerts() error {
	if a.config.dirPath != "" && a.config.keyFile!= "" && a.config.certFile != "" {
		keyPath := a.config.dirPath + "/" + a.config.keyFile
		tlsKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("cannot load certificate key from '%v': %w", keyPath, err)
		}
		certPath := a.config.dirPath + "/" + a.config.certFile
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

func (a *CertManager) setTlsKeyPair(cert tls.Certificate) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.tlsKeyPair = cert
}

func (a *CertManager) watchFiles() {
	defer a.doneWg.Done()
	for {
		select {
		case <-a.done:
			return
		// watch for events
		case event := <-a.watcher.Events:
			switch event.Op {
			case fsnotify.Create:
				if strings.Contains(event.Name, a.config.keyFile) {
					a.tlsKey, _ = ioutil.ReadFile(a.config.dirPath + "/" + a.config.keyFile)
				}

				if strings.Contains(event.Name, a.config.certFile) {
					a.tlsCert, _ = ioutil.ReadFile(a.config.dirPath + "/" + a.config.certFile)
				}

			case fsnotify.Remove:
				if strings.Contains(event.Name, a.config.keyFile) {
					a.tlsKey = nil
				}

				if strings.Contains(event.Name, a.config.certFile) {
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
