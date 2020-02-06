package file

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-ocf/kit/security"
)

// Config provides configuration of a file based Certificate manager
type Config struct {
	CAPool          string `envconfig:"CA_POOL" long:"tls-file_ca-pool" description:"file path to the root certificate in PEM format"`
	TLSKeyFileName  string `envconfig:"CERT_KEY_NAME" long:"tls-file-cert-key-name" description:"file name of private key in PEM format"`
	DirPath         string `envconfig:"CERT_DIR_PATH" long:"tls-file-cert-dir-path" description:"dir path where cert/key pair are saved"`
	TLSCertFileName string `envconfig:"CERT_NAME" long:"tls-file-cert-name" description:"file name of certificate in PEM format"`
}

// CertManager holds certificates from filesystem watched for changes
type CertManager struct {
	mutex         sync.Mutex
	config        Config
	tlsKey        []byte
	tlsCert       []byte
	tlsKeyPair    tls.Certificate
	caAuthorities *x509.CertPool
	watcher       *fsnotify.Watcher
	doneWg        sync.WaitGroup
	done          chan struct{}
}

// NewCertManagerFromConfiguration creates a new certificate manager which watches for certs in a filesystem
func NewCertManagerFromConfiguration(config Config) (*CertManager, error) {
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

	fileCertMgr := &CertManager{
		watcher:       watcher,
		config:        config,
		caAuthorities: security.NewDefaultCertPool(cas),
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

// GetClientTLSConfig returns tls configuration for clients
func (a *CertManager) GetClientTLSConfig() tls.Config {
	return tls.Config{
		RootCAs:                  a.getCertificateAuthorities(),
		GetClientCertificate:     a.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}

// GetServerTLSConfig returns tls configuration for servers
func (a *CertManager) GetServerTLSConfig() tls.Config {
	return tls.Config{
		ClientCAs:      a.getCertificateAuthorities(),
		GetCertificate: a.getCertificate2,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
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

func (a *CertManager) getCertificateAuthorities() *x509.CertPool {
	return a.caAuthorities
}

func (a *CertManager) loadCerts() error {
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
		a.tlsKeyPair = cert
	}
	return nil
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
					a.tlsKeyPair = cert
				}
			}
		}
	}
}
