package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/plgd-dev/kit/security"
)

// Config provides configuration of a file based Client Certificate manager
type ClientConfig struct {
	Enabled                   	bool 	`yaml:"enabled" json:"enabled" default:"true"`
	CAFile                    	string 	`yaml:"caFile" json:"caFile" description:"file path to the root certificate in PEM format"`
	KeyFile                   	string 	`yaml:"keyFile" json:"keyFile" description:"file name of private key in PEM format"`
	CertFile                  	string 	`yaml:"certFile" json:"certFile" description:"file name of certificate in PEM format"`
	UseSystemCAPool           	bool   	`yaml:"useSystemCAPool" json:"useSystemCAPool" description:"use system certification pool"`
}

// CertManager holds certificates from filesystem watched for changes
type ClientCertManager struct {
	mutex                   sync.Mutex
	config                  ClientConfig
	tlsKey                  []byte
	tlsCert                 []byte
	tlsKeyPair              tls.Certificate
	certificateAuthorities  []*x509.Certificate
	watcher                 *fsnotify.Watcher
	doneWg                  sync.WaitGroup
	done                    chan struct{}
	newCaCertPoolFunc       func() *x509.CertPool
}

// NewCertManagerFromConfiguration creates a new certificate manager which watches for certs in a filesystem
func NewCertManagerFromConfiguration(config ClientConfig) (*ClientCertManager, error) {
	var cas []*x509.Certificate
	if config.CAFile != "" {
		certs, err := security.LoadX509(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate authorities from '%v': %w", config.CAFile, err)
		}
		cas = certs
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	newCaCertPool := func() *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range cas {
			p.AddCert(c)
		}
		return p
	}
	if config.UseSystemCAPool {
		newCaCertPool = func() *x509.CertPool {
			return security.NewDefaultCertPool(cas)
		}
	}

	fileCertMgr := &ClientCertManager{
		watcher:                 watcher,
		config:                  config,
		newCaCertPoolFunc:       newCaCertPool,
		certificateAuthorities:  cas,
	}
	err = fileCertMgr.loadCerts()
	if err != nil {
		return nil, err
	}

	if err := fileCertMgr.watcher.Add(filepath.Dir(config.CAFile)); err != nil {
		return nil, err
	}
	if err := fileCertMgr.watcher.Add(filepath.Dir(config.CertFile)); err != nil {
		return nil, err
	}
	if err := fileCertMgr.watcher.Add(filepath.Dir(config.KeyFile)); err != nil {
		return nil, err
	}

	fileCertMgr.done = make(chan struct{})
	fileCertMgr.doneWg.Add(1)

	go fileCertMgr.watchFiles()

	return fileCertMgr, nil
}

// GetCertificateAuthorities returns certificates authorities
func (a *ClientCertManager) GetCertificateAuthorities() []*x509.Certificate {
	return a.certificateAuthorities
}

// GetClientTLSConfig returns tls configuration for clients
func (a *ClientCertManager) GetClientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:                  a.newCaCertPoolFunc(),
		GetClientCertificate:     a.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}

// Close ends watching certificates
func (a *ClientCertManager) Close() {
	if a.done != nil {
		_ = a.watcher.Close()
		close(a.done)
		a.doneWg.Wait()
	}
}

func (a *ClientCertManager) getCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *ClientCertManager) loadCerts() error {
	if a.config.KeyFile!= "" && a.config.CertFile != "" {
		keyPath := a.config.KeyFile
		tlsKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("cannot load certificate key from '%v': %w", keyPath, err)
		}
		certPath := a.config.CertFile
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

func (a *ClientCertManager) setTlsKeyPair(cert tls.Certificate) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.tlsKeyPair = cert
}

func (a *ClientCertManager) watchFiles() {
	defer a.doneWg.Done()
	for {
		select {
		case <-a.done:
			return
		// watch for events
		case event := <-a.watcher.Events:
			switch event.Op {
			case fsnotify.Create:
				if strings.Contains(event.Name, a.config.KeyFile) {
					a.tlsKey, _ = ioutil.ReadFile(a.config.KeyFile)
				}

				if strings.Contains(event.Name, a.config.CertFile) {
					a.tlsCert, _ = ioutil.ReadFile(a.config.CertFile)
				}

				if strings.Contains(event.Name, a.config.CAFile) {
					a.certificateAuthorities, _ = security.LoadX509(a.config.CAFile)
				}

			case fsnotify.Remove:
				if strings.Contains(event.Name, a.config.KeyFile) {
					a.tlsKey = nil
				}

				if strings.Contains(event.Name, a.config.CertFile) {
					a.tlsCert = nil
				}

				if strings.Contains(event.Name, a.config.CAFile) {
					a.certificateAuthorities = nil
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
