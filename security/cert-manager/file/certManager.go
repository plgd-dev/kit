package file

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/fsnotify/fsnotify"
	"github.com/go-ocf/kit/security"
	"io/ioutil"
	"strings"
	"sync"
)

// CertManager holds certificates from filesystem watched for changes
type CertManager struct {
	mutex           sync.Mutex
	tlsKey          []byte
	tlsCert         []byte
	tlsKeyPair      tls.Certificate
	caAuthorities   *x509.CertPool
	watcher         *fsnotify.Watcher
	tlsKeyFileName  string
	dirPath         string
	tlsCertFileName string
	doneWg          sync.WaitGroup
	done            chan struct{}
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
				if strings.Contains(event.Name, a.tlsKeyFileName) {
					a.tlsKey, _ = ioutil.ReadFile(a.dirPath + "/" + a.tlsKeyFileName)
				}

				if strings.Contains(event.Name, a.tlsCertFileName) {
					a.tlsCert, _ = ioutil.ReadFile(a.dirPath + "/" + a.tlsCertFileName)
				}

			case fsnotify.Remove:
				if strings.Contains(event.Name, a.tlsKeyFileName) {
					a.tlsKey = nil
				}

				if strings.Contains(event.Name, a.tlsCertFileName) {
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

	fileCertMgr := &CertManager{
		watcher:         watcher,
		tlsKeyFileName:  tlsKeyFileName,
		dirPath:         dirPath,
		tlsCertFileName: tlsCertFileName,
		caAuthorities:   security.NewDefaultCertPool(cas),
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
