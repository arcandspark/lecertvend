package lecertvend

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"strings"
)

type CertStorage struct {
	vcli    *vault.Client
	mount   string
	prefix  string
	cfToken string
}

// domainFromPrefix will extract the DNS domain name from the Vault secret prefix
// provided by the caller. Minor validation is done to make sure it looks a little
// like a DNS domain.
func domainFromPrefix(prefix string) (string, error) {
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

// NewCertStorage creates a CertStorage with a configured backend, or
// returns an error if configuration failed.
//
// NOTE: The setup of Vault in this implementation requires that Vault configuration
// is provided via the environment variables VAULT_ADDR and VAULT_TOKEN
func NewCertStorage(mount string, prefix string) (CertStorage, error) {
	var cs CertStorage

	// Create the vault client
	cfg := vault.DefaultConfig()
	vcli, err := vault.NewClient(cfg)
	if err != nil {
		return cs, fmt.Errorf("error creating Vault client: %v", err)
	}
	cs.vcli = vcli

	if len(mount) == 0 {
		return cs, fmt.Errorf("mount cannot be empty")
	}
	if len(prefix) == 0 {
		return cs, fmt.Errorf("prefix cannot be empty")
	}
	cs.mount = mount
	cs.prefix = prefix

	// Read the cftoken from the prefix path. Depending on if this is a vend or a
	// renew, the cftoken secret will either be at the prefix location, or one level
	// above the prefix.
	cfTokenPath := prefix + "/cftoken"
	sec, err := cs.getSecret(cfTokenPath)
	if err != nil {
		if strings.Count(prefix, "/") >= 1 {
			lastSlashIdx := strings.LastIndex(prefix, "/")
			parentPrefix := prefix[0:lastSlashIdx]
			cfTokenPath = parentPrefix + "/cftoken"
			sec, err = cs.getSecret(cfTokenPath)

			if err != nil {
				return cs, fmt.Errorf("unable to locate cftoken secret at %v or %v: %v", prefix, parentPrefix, err)
			}
		}
	}

	// If we found a cftoken secret, validate the contents
	cfToken, ok := sec.Data["token"].(string)
	if !ok {
		return cs, fmt.Errorf("%v does not contain \"token\" key, or value is not a string", cfTokenPath)
	}
	if len(cfToken) == 0 {
		return cs, fmt.Errorf("token value from %v is empty", cfTokenPath)
	}
	cs.cfToken = cfToken

	return cs, nil
}

func (cs CertStorage) getSecret(path string) (*vault.KVSecret, error) {
	sec, err := cs.vcli.KVv2(cs.mount).Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if sec.Data == nil {
		return nil, fmt.Errorf("secret at %v is deleted", path)
	}
	return sec, nil
}

// List lists the contents in a kv2 secret engine at the specified prefix
// The prefix should be given as used in the CLI, this function takes care
// of mapping it to the correct API path.
func (cs CertStorage) List(prefix string) []string {
	contents := []string{}
	secs, err := cs.vcli.Logical().List(cs.mount + "/metadata/" + prefix)
	if err == nil {
		if keyList, ok := secs.Data["keys"].([]interface{}); ok {
			for _, v := range keyList {
				if sv, ok := v.(string); ok {
					contents = append(contents, sv)
				}
			}
		}
	}
	return contents
}

func getCertPEMString(secret *vault.KVSecret) (string, error) {
	certPEM, ok := secret.Data["cert"].(string)
	if !ok {
		return "", fmt.Errorf("secret \"cert\" key is missing or not a string")
	}
	if len(certPEM) == 0 {
		return "", fmt.Errorf("secret \"cert\" key is empty")
	}

	return certPEM, nil
}

func decodeCerts(pemBytes []byte, certList []*x509.Certificate) ([]*x509.Certificate, error) {
	p, rest := pem.Decode(pemBytes)
	if p == nil {
		return certList, nil
	} else {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %v", err)
		}
		return decodeCerts(rest, append(certList, cert))
	}
}

// GetCerts returns parsed certificated from a secret in the vault.
//
// The order of the returned slice will be such that the cert at index 0 will be the first
// cert that appeared in the PEM data in the secret. Subsequent indexes will contain certs
// in the same order in which they appeared in the PEM data.
//
// This utility treats the cert at index 0 as the cert which the caller intends to
// operate on. Generally, other applications consuming PEM encoded cert chains
// expect the first certificate to be the subject.
func (cs CertStorage) GetCerts(path string) ([]*x509.Certificate, error) {
	var certList []*x509.Certificate

	sec, err := cs.getSecret(path)
	if err != nil {
		return nil, fmt.Errorf("error getting secret at %v: %v", path, err)
	}
	certPEM, err := getCertPEMString(sec)
	if err != nil {
		return nil, fmt.Errorf("error getting cert PEM data: %v", err)
	}

	certList, err = decodeCerts([]byte(certPEM), certList)
	if err != nil {
		return nil, fmt.Errorf("error decoding certs at %v: %v", path, err)
	}

	return certList, nil
}

func (cs CertStorage) CFToken() string {
	return cs.cfToken
}
