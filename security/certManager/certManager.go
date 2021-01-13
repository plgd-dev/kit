package certManager

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

// CertManager holds certificates from filesystem watched for changes
type FileCertManager struct {
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
func NewCertManagerFromConfiguration(config Config) (*FileCertManager, error) {
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

	verifyClientCertificate := tls.RequireAndVerifyClientCert
	if !config.ClientCertificateRequired {
		verifyClientCertificate = tls.NoClientCert
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

	fileCertMgr := &FileCertManager{
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
func (a *FileCertManager) GetCertificateAuthorities() []*x509.Certificate {
	return a.certificateAuthorities
}

// GetClientTLSConfig returns tls configuration for clients
func (a *FileCertManager) GetClientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:                  a.newCaCertPoolFunc(),
		GetClientCertificate:     a.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}

// GetServerTLSConfig returns tls configuration for servers
func (a *FileCertManager) GetServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:      a.newCaCertPoolFunc(),
		GetCertificate: a.getCertificate2,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     a.verifyClientCertificate,
	}
}

// Close ends watching certificates
func (a *FileCertManager) Close() {
	if a.done != nil {
		_ = a.watcher.Close()
		close(a.done)
		a.doneWg.Wait()
	}
}

func (a *FileCertManager) getCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *FileCertManager) getCertificate2(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return &a.tlsKeyPair, nil
}

func (a *FileCertManager) loadCerts() error {
	if a.config.DirPath != "" && a.config.KeyFile!= "" && a.config.CertFile != "" {
		keyPath := a.config.DirPath + "/" + a.config.KeyFile
		tlsKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("cannot load certificate key from '%v': %w", keyPath, err)
		}
		certPath := a.config.DirPath + "/" + a.config.CertFile
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

func (a *FileCertManager) setTlsKeyPair(cert tls.Certificate) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.tlsKeyPair = cert
}

func (a *FileCertManager) watchFiles() {
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
					a.tlsKey, _ = ioutil.ReadFile(a.config.DirPath + "/" + a.config.KeyFile)
				}

				if strings.Contains(event.Name, a.config.CertFile) {
					a.tlsCert, _ = ioutil.ReadFile(a.config.DirPath + "/" + a.config.CertFile)
				}

			case fsnotify.Remove:
				if strings.Contains(event.Name, a.config.KeyFile) {
					a.tlsKey = nil
				}

				if strings.Contains(event.Name, a.config.CertFile) {
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