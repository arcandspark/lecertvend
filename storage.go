package lecertvend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	contact string
	leKey   *ecdsa.PrivateKey
}

func (cs CertStorage) CFToken() string {
	return cs.cfToken
}

func (cs CertStorage) Contact() string {
	return cs.contact
}

func (cs CertStorage) LEKey() *ecdsa.PrivateKey {
	return cs.leKey
}

func decodePEMECKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	if len(pemData) == 0 {
		return nil, fmt.Errorf("pem data was empty")
	}

	b, _ := pem.Decode(pemData)
	if b == nil {
		return nil, fmt.Errorf("no PEM blocks in pemData, expected one for PRIVATE KEY")
	}
	if b.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("first PEM block of type %v, expected type PRIVATE KEY", b.Type)
	}

	privKey, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	return privKey, nil
}

func encodePEMECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	x509bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling key: %v", err)
	}
	b := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509bytes,
	}
	return pem.EncodeToMemory(&b), nil
}

type SecretGetError struct {
	Inner    error
	NotFound bool
}

func NewSecretGetError(err error) *SecretGetError {
	sge := &SecretGetError{
		Inner:    err,
		NotFound: false,
	}
	if strings.Contains(err.Error(), "secret not found") {
		sge.NotFound = true
	}
	return sge
}

func (e *SecretGetError) Error() string {
	return e.Inner.Error()
}

func (e *SecretGetError) Unwrap() error {
	return e.Inner
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

	// Read the lecertvend secret from the prefix path. Depending on if this is a vend or a
	// renew, the lecertvend secret will either be at the prefix location, or one level
	// above the prefix.
	lecvPath := prefix + "/lecertvend"
	sec, err := cs.getSecret(lecvPath)
	if err != nil {
		if strings.Count(prefix, "/") >= 1 {
			lastSlashIdx := strings.LastIndex(prefix, "/")
			parentPrefix := prefix[0:lastSlashIdx]
			lecvPath = parentPrefix + "/lecertvend"
			sec, err = cs.getSecret(lecvPath)

			if err != nil {
				return cs, fmt.Errorf("unable to locate lecertvend secret at %v or %v: %v", prefix, parentPrefix, err)
			}
		}
	}

	// If we found a lecertvend secret, validate the contents
	cfToken, ok := sec.Data["cfToken"].(string)
	if !ok {
		return cs, fmt.Errorf("%v does not contain \"cfToken\" key, or value is not a string", lecvPath)
	}
	if len(cfToken) == 0 {
		return cs, fmt.Errorf("cfToken value from %v is empty", lecvPath)
	}
	cs.cfToken = cfToken

	contact, ok := sec.Data["contact"].(string)
	if !ok {
		return cs, fmt.Errorf("%v does not contain \"contact\" key, or value is not a string", lecvPath)
	}
	if len(contact) == 0 {
		return cs, fmt.Errorf("contact value from %v is empty", lecvPath)
	}
	cs.contact = contact

	// leKey is optional, generate it if not present
	leKey, ok := sec.Data["leKey"].(string)
	if ok && len(leKey) > 0 {
		cs.leKey, err = decodePEMECKey([]byte(leKey))
		if err != nil {
			return cs, fmt.Errorf("error decoding leKey value from %v: %v", lecvPath, err)
		}
	} else {
		cs.leKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return cs, fmt.Errorf("error generating EC key: %v", err)
		}
		newKeyBytes, err := encodePEMECKey(cs.leKey)
		if err != nil {
			return cs, fmt.Errorf("generated new leKey, but failed to PEM encode it: %v", err)
		}
		err = cs.patchSecret(lecvPath, map[string]interface{}{
			"leKey": string(newKeyBytes),
		})
		if err != nil {
			return cs, fmt.Errorf("error updating secret with generated leKey: %v", err)
		}
	}

	return cs, nil
}

func (cs CertStorage) getSecret(path string) (*vault.KVSecret, error) {
	sec, err := cs.vcli.KVv2(cs.mount).Get(context.Background(), path)
	if err != nil {
		return nil, NewSecretGetError(err)
	}
	if sec.Data == nil {
		return nil, NewSecretGetError(fmt.Errorf("secret not found: secret at %v is deleted", path))
	}
	return sec, nil
}

func (cs CertStorage) patchSecret(path string, newData map[string]interface{}) error {
	_, err := cs.vcli.KVv2(cs.mount).Patch(context.Background(), path, newData)
	if err != nil {
		return fmt.Errorf("error updating secret at %v: %v", path, err)
	}
	return nil
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

// GetCerts returns parsed certificates from a secret in the vault.
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
		return nil, fmt.Errorf("error getting secret at %v: %w", path, err)
	}
	certPEM, err := getCertPEMString(sec)
	if err != nil {
		return nil, fmt.Errorf("error getting cert PEM data: %w", err)
	}

	certList, err = decodeCerts([]byte(certPEM), certList)
	if err != nil {
		return nil, fmt.Errorf("error decoding certs at %v: %w", path, err)
	}

	return certList, nil
}
