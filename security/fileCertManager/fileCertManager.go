package fileCertManager

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/fsnotify/fsnotify"
	"github.com/go-ocf/kit/security"
	"io/ioutil"
	"strings"
)

type FileCertManager struct {
	tlsKey []byte
	tlsCert []byte
	tlsKeyPair tls.Certificate
	caAuthorities *x509.CertPool
	watcher *fsnotify.Watcher
	tlsKeyFileName string
	dirPath string
	tlsCertFileName string
}

// Close the certificate watching
func (a *FileCertManager) CloseManager() {
	_ = a.watcher.Close()
}

func (a *FileCertManager) watchFiles() {
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
		}
	}
}

// Create a new certificate manager which watches for certs in a filesystem
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

	go fileCertMgr.watchFiles()

	return fileCertMgr,nil
}

func (a *FileCertManager) GetCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &a.tlsKeyPair, nil
}

// GetCertificate locks around returning a tls.Certificate; use as tls.Config.GetCertificate.
func (a *FileCertManager) GetCertificate2(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &a.tlsKeyPair, nil
}

func (a *FileCertManager) GetCertificateAuthorities() *x509.CertPool {
	return a.caAuthorities
}


func (a *FileCertManager) GetClientTLSConfig() tls.Config {
	return tls.Config {
		RootCAs:                  a.GetCertificateAuthorities(),
		GetClientCertificate:     a.GetCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}
func (a *FileCertManager) GetServerTLSConfig() tls.Config {
	return tls.Config{
		ClientCAs:      a.GetCertificateAuthorities(),
		GetCertificate: a.GetCertificate2,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	}
}