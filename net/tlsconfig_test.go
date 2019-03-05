package net

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testSetupTLS(t *testing.T, dir string) TLSConfig {
	crt := filepath.Join(dir, "cert.crt")
	if err := ioutil.WriteFile(crt, CertPEMBlock, 0600); err != nil {
		assert.NoError(t, err)
	}
	crtKey := filepath.Join(dir, "cert.key")
	if err := ioutil.WriteFile(crtKey, KeyPEMBlock, 0600); err != nil {
		assert.NoError(t, err)
	}
	caRootCrt := filepath.Join(dir, "caRoot.crt")
	if err := ioutil.WriteFile(caRootCrt, CARootPemBlock, 0600); err != nil {
		assert.NoError(t, err)
	}
	caInterCrt := filepath.Join(dir, "caInter.crt")
	if err := ioutil.WriteFile(caInterCrt, CAIntermediatePemBlock, 0600); err != nil {
		assert.NoError(t, err)
	}

	return TLSConfig{
		Certificate:    crt,
		CertificateKey: crtKey,
		CAPool:         dir,
	}
}

var (
	CertPEMBlock = []byte(`-----BEGIN CERTIFICATE-----
MIIBkzCCATegAwIBAgIUF399tsbWkMnMF6NWt6j/MbUIZvUwDAYIKoZIzj0EAwIF
ADARMQ8wDQYDVQQDEwZSb290Q0EwHhcNMTgwNzAyMDUzODQwWhcNMjgwNzAyMDUz
ODQwWjA0MTIwMAYDVQQDEyl1dWlkOjYxNTVmMjFjLTA3MjItNDZjOC05ZDcxLTMw
NGE1NTMyNzllOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBTvmtgfe49ZY0L0
B7wC/XH5V1jJ3NFdLyPZZFmz9O731JB7dwGYVUtaRai5cPM349mIw9k5kX8Zww7E
wMf4jw2jSDBGMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgGIMCkGA1UdJQQiMCAG
CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGC3nwBBjAMBggqhkjOPQQDAgUAA0gA
MEUCIBPNUqmjeTFIMkT3Y1qqUnR/fQmqbhxR8gScBsz8m3w8AiEAlH3Nf57vFqqh
tuvff9aSBdNlDBlQ5dTLu24V7fScLLI=
-----END CERTIFICATE-----`)

	KeyPEMBlock = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGqPsr+N0x/CBmykEGm04TXvsykwxwqAy32SpVO2ANB0oAoGCCqGSM49
AwEHoUQDQgAEFO+a2B97j1ljQvQHvAL9cflXWMnc0V0vI9lkWbP07vfUkHt3AZhV
S1pFqLlw8zfj2YjD2TmRfxnDDsTAx/iPDQ==
-----END EC PRIVATE KEY-----`)

	CARootPemBlock = []byte(`-----BEGIN CERTIFICATE-----
MIIBazCCAQ+gAwIBAgIUY9HA4Of2KwJm5HaP72+VkLpUCpYwDAYIKoZIzj0EAwIF
ADARMQ8wDQYDVQQDEwZSb290Q0EwHhcNMTgwNjIyMTEyMzM1WhcNMjgwNjIyMTEy
MzM1WjARMQ8wDQYDVQQDEwZSb290Q0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAREWwFfs+rAjPZ80alM/dQEWFOILkpkkwadCGomdiEBwLdlJEKGHomcVNJ39xBV
nte6BA4fOP7a9kdrsbRe/qKao0MwQTAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQE
AwIBBjAhBgNVHSUEGjAYBgorBgEEAYLefAEGBgorBgEEAYLefAEHMAwGCCqGSM49
BAMCBQADSAAwRQIgI95uRXx5y4iehqKq1CP99agqlPGc8JaMMIzvwn5lYBICIQC8
KokSEk+DVrYiWUubIxl/tSCtwC8jyA2jKO7CY63cQg==
-----END CERTIFICATE-----
`)

	CAIntermediatePemBlock = []byte(`-----BEGIN CERTIFICATE-----
MIIBdzCCARqgAwIBAgIUMFZsksJ1spFMlONPi+v0EkDcD+EwDAYIKoZIzj0EAwIF
ADARMQ8wDQYDVQQDEwZSb290Q0EwHhcNMTgwNjIyMTEyNDMwWhcNMjgwNjIyMTEy
NDMwWjAZMRcwFQYDVQQDEw5JbnRlcm1lZGlhdGVDQTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABBRR8WmmkmVWvFvdi1YyanKOV3FOiMwZ1blfAOnfUhWjBv2AVLJG
bRZ/fo+7BF8peD/BYQkbs1KAkH/nxnDeQLyjRjBEMA8GA1UdEwQIMAYBAf8CAQAw
DgYDVR0PAQH/BAQDAgEGMCEGA1UdJQQaMBgGCisGAQQBgt58AQYGCisGAQQBgt58
AQcwDAYIKoZIzj0EAwIFAANJADBGAiEA8VNPyaUzaIUOsqdvoaT3dCZDBbLjOx8R
XVqB37LdYPcCIQDiqvcbW0aOfVcvMDVs3r1HavgKuTIHgJ9uzSOAAF17vg==
-----END CERTIFICATE-----
`)
)
