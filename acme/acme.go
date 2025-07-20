package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	domainrouter "github.com/pablu23/domain-router"
)

func SetupAcme(config *domainrouter.Config) error {
	acme := config.Server.Ssl.Acme

	var privateKey *ecdsa.PrivateKey
	if _, err := os.Stat(acme.KeyFile); errors.Is(err, os.ErrNotExist) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		err = os.WriteFile(acme.KeyFile, []byte(encode(privateKey)), 0666)
		if err != nil {
			return err
		}
	} else {
		keyBytes, err := os.ReadFile(acme.KeyFile)
		if err != nil {
			return err
		}
		privateKey = decode(string(keyBytes))
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
		return err
	}

	// strconv.Itoa(config.Server.Port)
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "5002"))
	if err != nil {
		return err
	}

	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "5001"))
	if err != nil {
		return err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
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
		return err
	}

	fmt.Printf("%#v\n", certificates)
	return nil
}

func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func decode(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	return privateKey
}
