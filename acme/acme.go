package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	domainrouter "github.com/pablu23/domain-router"
)

type Acme struct {
	user         *User
	client       *lego.Client
	domains      []string
	certFilePath string
	keyFilePath  string
	renewTicker  *time.Ticker
}

func SetupAcme(config *domainrouter.Config) (*Acme, error) {
	acme := config.Server.Ssl.Acme
	var privateKey *ecdsa.PrivateKey
	if _, err := os.Stat(acme.KeyFile); errors.Is(err, os.ErrNotExist) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(acme.KeyFile, []byte(encodePrivKey(privateKey)), 0666)
		if err != nil {
			return nil, err
		}
	} else {
		keyBytes, err := os.ReadFile(acme.KeyFile)
		if err != nil {
			return nil, err
		}
		privateKey = decodePrivKey(string(keyBytes))
	}

	user := User{
		Email: acme.Email,
		key:   privateKey,
	}

	leConfig := lego.NewConfig(&user)
	leConfig.CADirURL = acme.CADirURL
	leConfig.Certificate.KeyType = certcrypto.RSA2048
	leConfig.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client, err := lego.NewClient(leConfig)
	if err != nil {
		return nil, err
	}

	// strconv.Itoa(config.Server.Port)
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", acme.Http01Port))
	if err != nil {
		return nil, err
	}

	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", acme.TlsAlpn01Port))
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	user.Registration = reg

	domains := make([]string, 0)
	for _, host := range config.Hosts {
		domains = append(domains, host.Domains...)
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(config.Server.Ssl.CertFile, certificates.Certificate, 0666)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(config.Server.Ssl.KeyFile, certificates.PrivateKey, 0666)
	if err != nil {
		return nil, err
	}

	d, err := time.ParseDuration(acme.RenewTime)
	if err != nil {
		return nil, err
	}

	return &Acme{
		user:         &user,
		client:       client,
		domains:      domains,
		certFilePath: config.Server.Ssl.CertFile,
		keyFilePath:  config.Server.Ssl.KeyFile,
		renewTicker:  time.NewTicker(d),
	}, nil
}

func (a *Acme) RenewAcme() error {
	request := certificate.ObtainRequest{
		Domains: a.domains,
		Bundle:  true,
	}

	certificates, err := a.client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	err = os.WriteFile(a.certFilePath, certificates.Certificate, 0666)
	if err != nil {
		return err
	}

	err = os.WriteFile(a.keyFilePath, certificates.PrivateKey, 0666)
	if err != nil {
		return err
	}

	return nil
}

func (a *Acme) RegisterTicker() {
	for {
		select {
		case <-a.renewTicker.C:
			a.RenewAcme()
		}
	}
}

func encodePrivKey(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func decodePrivKey(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	return privateKey
}
