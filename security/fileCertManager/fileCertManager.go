package fileCertManager

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/fsnotify/fsnotify"
	"github.com/go-ocf/kit/security"
	"io/ioutil"
	"strings"
	"sync"
)

// FileCertManager holds certificates from filesystem watched for changes
type FileCertManager struct {
	mutex sync.Mutex
	tlsKey []byte
	tlsCert []byte
	tlsKeyPair tls.Certificate
	caAuthorities *x509.CertPool
	watcher *fsnotify.Watcher
	tlsKeyFileName string
	dirPath string
	tlsCertFileName string
	doneWg sync.WaitGroup
	done chan struct{}
}

// Close ends watching certificates
func (a *FileCertManager) Close() {
	if a.done != nil {
		_ = a.watcher.Close()
		close(a.done)
		a.doneWg.Wait()
	}
}

func (a *FileCertManager) watchFiles() {
	defer a.doneWg.Done()
	for {
		select {
		// watch for events
		case event := <-a.watcher.Events:
			{
				if event.Op == fsnotify.Create {
					if strings.Contains(event.Name, a.tlsKeyFileName) {
						a.tlsKey, _ = ioutil.ReadFile(a.dirPath + "/" + a.tlsKeyFileName)
					}

					if strings.Contains(event.Name, a.tlsCertFileName) {
						a.tlsCert, _ = ioutil.ReadFile(a.dirPath + "/" + a.tlsCertFileName)
					}
				}

				if event.Op == fsnotify.Remove {
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
		case <-a.done:
			return
		}
	}
}

// NewFileCertManager creates a new certificate manager which watches for certs in a filesystem
func NewFileCertManager(cas []*x509.Certificate, dirPath string, tlsKeyFileName string, tlsCertFileName string) (_ *FileCertManager, mgrErr error) {

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	fileCertMgr := &FileCertManager{
		watcher:         watcher,
		tlsKeyFileName:  tlsKeyFileName,
		dirPath:         dirPath,
		tlsCertFileName: tlsCertFileName,
		caAuthorities: security.NewDefaultCertPool(cas),
	}

	if err := fileCertMgr.watcher.Add(dirPath); err != nil {
		return nil,err
	}

	fileCertMgr.done = make(chan struct{})
	fileCertMgr.doneWg.Add(1)

	go fileCertMgr.watchFiles()

	return fileCertMgr,nil
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

func (a *FileCertManager) getCertificateAuthorities() *x509.CertPool {
	return a.caAuthorities
}

// GetClientTLSConfig returns tls configuration for clients
func (a *FileCertManager) GetClientTLSConfig() tls.Config {
	return tls.Config {
		RootCAs:                  a.getCertificateAuthorities(),
		GetClientCertificate:     a.getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}

// GetServerTLSConfig returns tls configuration for servers
func (a *FileCertManager) GetServerTLSConfig() tls.Config {
	return tls.Config{
		ClientCAs:      a.getCertificateAuthorities(),
		GetCertificate: a.getCertificate2,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	}
}