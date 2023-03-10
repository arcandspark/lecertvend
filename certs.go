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
const LEStagingEndpoint = "https://acme-staging-v02.api.letsencrypt.org/directory"

func CertValidDaysRemaining(cert *x509.Certificate) int {
	remDur := cert.NotAfter.Sub(time.Now())
	return int(remDur.Hours() / 24)
}

// ZoneFromPrefix will extract the DNS domain name from the Vault secret prefix
// provided by the caller. Minor validation is done to make sure it looks a little
// like a DNS domain.
func ZoneFromPrefix(prefix string) (string, error) {
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

// NamesFromCert returns a comma separated list of host part names given a certificate.
//
// This returns the name list exactly how it would be given to lecertvend on the command
// line in the -names flag, and so this output can be passed directly to Vend()
func NamesFromCert(cert *x509.Certificate, zone string) (string, error) {
	var nameList []string
	if cert == nil {
		return "", fmt.Errorf("cert was nil")
	}
	for _, v := range cert.DNSNames {
		if v == zone {
			nameList = append(nameList, ".")
		} else {
			if !strings.HasSuffix(v, "."+zone) {
				return "", fmt.Errorf("cert name %v does not have zone part %v", v, zone)
			}
			if len(v) <= len(zone)+1 {
				return "", fmt.Errorf("host part of %v is empty", v)
			}
			nameList = append(nameList, v[0:len(v)-len(zone)-1])
		}
	}

	return strings.Join(nameList, ","), nil
}

type CertKeyPair struct {
	CertChainPEM []byte
	PrivKeyPEM   []byte
}

type CertVendingMachine struct {
	zone         string
	contact      string
	cfToken      string
	leKey        *ecdsa.PrivateKey
	solver       *DNS01Solver
	ACMEEndpoint string
}

func NewCertVendingMachine(zone string, contact string, cfToken string, leKey *ecdsa.PrivateKey) (CertVendingMachine, error) {
	var cvm CertVendingMachine
	cvm.ACMEEndpoint = LEProductionEndpoint

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
		Zone:        cvm.zone,
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
			Directory: cvm.ACMEEndpoint,
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
	if len(certs) == 0 {
		return ckp, fmt.Errorf("no certs and no error returned from ACME client ??\\_(???)_/??")
	}
	// I just expect the first cert entry to contain the full chain
	// The other option here would be to parse all the chains and make sure one of them
	// starts with the requested subject's cert
	ckp.CertChainPEM = certs[0].ChainPEM

	return ckp, nil
}
