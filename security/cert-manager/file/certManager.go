package file

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-ocf/kit/security"
)

// Config provides configuration of a file based Certificate manager
type Config struct {
	TLSKeyFileName  string
	DirPath         string
	TLSCertFileName string
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

// Close ends watching certificates
func (a *CertManager) Close() {
	if a.done != nil {
		_ = a.watcher.Close()
		close(a.done)
		a.doneWg.Wait()
	}
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
				cert, ert := tls.X509KeyPair(a.tlsCert, a.tlsKey)
				if ert == nil {
					a.tlsKeyPair = cert
				}
			}
		}
	}
}

// NewFileCertManager creates a new certificate manager which watches for certs in a filesystem
func NewFileCertManager(cas []*x509.Certificate, dirPath string, tlsKeyFileName string, tlsCertFileName string) (_ *CertManager, mgrErr error) {

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	config := Config{
		TLSKeyFileName:  tlsKeyFileName,
		DirPath:         dirPath,
		TLSCertFileName: tlsCertFileName,
	}

	fileCertMgr := &CertManager{
		watcher:       watcher,
		config:        config,
		caAuthorities: security.NewDefaultCertPool(cas),
	}

	if err := fileCertMgr.watcher.Add(dirPath); err != nil {
		return nil, err
	}

	fileCertMgr.done = make(chan struct{})
	fileCertMgr.doneWg.Add(1)

	go fileCertMgr.watchFiles()

	return fileCertMgr, nil
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
