package lecertvend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/libdns/cloudflare"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"strings"
	"time"
)

const LEProductionEndpoint = "https://acme-v02.api.letsencrypt.org/directory"

func CertValidDaysRemaining(cert *x509.Certificate) int {
	remDur := cert.NotAfter.Sub(time.Now())
	return int(remDur.Hours() / 24)
}

// DomainFromPrefix will extract the DNS domain name from the Vault secret prefix
// provided by the caller. Minor validation is done to make sure it looks a little
// like a DNS domain.
func DomainFromPrefix(prefix string) (string, error) {
	prefixParts := strings.Split(prefix, "/")
	prefixPartCount := len(prefixParts)
	if prefixPartCount < 2 {
		return "", fmt.Errorf("prefix expected to be at least two levels deep: example/example.com")
	}

	domain := prefixParts[prefixPartCount-1]
	if len(domain) == 0 {
		return "", fmt.Errorf("domain part of prefix is empty")
	}
	if !strings.ContainsAny(domain, ".") {
		return "", fmt.Errorf("domain \"%v\" contains not dots, are you sure you own a TLD?", domain)
	}

	return domain, nil
}

type CertKeyPair struct {
	CertChainPEM []byte
	PrivKeyPEM   []byte
}

type CertVendingMachine struct {
	zone    string
	contact string
	cfToken string
	leKey   *ecdsa.PrivateKey
	solver  *DNS01Solver
}

func NewCertVendingMachine(zone string, contact string, cfToken string, leKey *ecdsa.PrivateKey) (CertVendingMachine, error) {
	var cvm CertVendingMachine

	if len(zone) == 0 {
		return cvm, fmt.Errorf("zone must be provided")
	}
	cvm.zone = strings.Trim(zone, ".")

	if len(contact) == 0 {
		return cvm, fmt.Errorf("contact email must be provided")
	}
	cvm.contact = contact

	if len(cfToken) == 0 {
		return cvm, fmt.Errorf("CloudFlare API token must be provided")
	}
	cvm.cfToken = cfToken

	if leKey == nil {
		return cvm, fmt.Errorf("Let's Encrypt accoutn private key must be provided")
	}
	cvm.leKey = leKey

	cvm.solver = &DNS01Solver{
		DNSProvider: &cloudflare.Provider{APIToken: cvm.cfToken},
	}

	return cvm, nil
}

func (cvm CertVendingMachine) VendCert(names []string) (CertKeyPair, error) {
	var ckp CertKeyPair
	if len(names) == 0 {
		return ckp, fmt.Errorf("a list of host names for which to issue a cert must be provided")
	}
	fqdnList := make([]string, len(names))
	for i, _ := range names {
		if names[i] == "." {
			fqdnList[i] = cvm.zone
		} else {
			fqdnList[i] = names[i] + "." + cvm.zone
		}
		fmt.Printf("Certificate Request DNS Name Included: %v\n", fqdnList[i])
	}

	ac := acmez.Client{
		Client: &acme.Client{
			Directory: LEProductionEndpoint,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDNS01: cvm.solver,
		},
	}

	accountTempl := acme.Account{
		Contact:              []string{"mailto:" + cvm.contact},
		PrivateKey:           cvm.leKey,
		TermsOfServiceAgreed: true,
	}

	// Get the account from the provided details, or create it if it does not yet exist
	// Each account will be unique to the combination of contact email and leKey
	// Multiple accounts can exist with the same contact details
	account, err := ac.GetAccount(context.Background(), accountTempl)
	if err != nil {
		if strings.Contains(err.Error(), "urn:ietf:params:acme:error:accountDoesNotExist") {
			// Need to create account
			account, err = ac.NewAccount(context.Background(), accountTempl)
			if err != nil {
				return ckp, fmt.Errorf("error creating account for %v: %w", accountTempl.Contact, err)
			}
		} else {
			// Something went wrong
			return ckp, fmt.Errorf("error getting account: %w", err)
		}
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ckp, fmt.Errorf("error generating private key for new cert: %w", err)
	}
	ckp.PrivKeyPEM, err = EncodePEMECKey(privKey)
	if err != nil {
		return ckp, fmt.Errorf("error PEM encoding private key: %w", err)
	}

	certs, err := ac.ObtainCertificate(context.Background(), account, privKey, fqdnList)
	if err != nil {
		return ckp, fmt.Errorf("error issuing cert: %w", err)
	}
	for i, _ := range certs {
		fmt.Printf("Certs entry %v:\n", i)
		fmt.Println(certs[i].URL)
		fmt.Println(certs[i].ChainPEM)
	}

	return ckp, nil
}
