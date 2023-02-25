package lecertvend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"strings"
)

type SecretGetError struct {
	Inner    error
	NotFound bool
}

func SecretGetErrorWrap(err error) *SecretGetError {
	sge := &SecretGetError{
		Inner:    err,
		NotFound: false,
	}
	if strings.Contains(err.Error(), "secret not found") {
		sge.NotFound = true
	}
	return sge
}

// GetSecretString returns the requested key from a secret as a string,
// and also a bool indicating true if the value was present and could be
// asserted to be a string.
func GetSecretString(data map[string]interface{}, key string) (string, bool) {
	val, ok := data[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	if !ok {
		return "", false
	}
	return str, true
}

type CertStorage struct {
	vcli    *vault.Client
	mount   string
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
		} else {
			return cs, fmt.Errorf("unable to locate lecertvend secret at %v: %v", prefix, err)
		}
	}

	// If we found a lecertvend secret, validate the contents
	cfToken, ok := GetSecretString(sec.Data, "cfToken")
	if !ok {
		return cs, fmt.Errorf("%v does not contain \"cfToken\" key, or value is not a string", lecvPath)
	}
	if len(cfToken) == 0 {
		return cs, fmt.Errorf("cfToken value from %v is empty", lecvPath)
	}
	cs.cfToken = cfToken

	contact, ok := GetSecretString(sec.Data, "contact")
	if !ok {
		return cs, fmt.Errorf("%v does not contain \"contact\" key, or value is not a string", lecvPath)
	}
	if len(contact) == 0 {
		return cs, fmt.Errorf("contact value from %v is empty", lecvPath)
	}
	cs.contact = contact

	// leKey is optional, generate it if not present
	leKey, ok := GetSecretString(sec.Data, "leKey")
	if ok && len(leKey) > 0 {
		cs.leKey, err = DecodePEMECKey([]byte(leKey))
		if err != nil {
			return cs, fmt.Errorf("error decoding leKey value from %v: %v", lecvPath, err)
		}
	} else {
		cs.leKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return cs, fmt.Errorf("error generating EC key: %v", err)
		}
		newKeyBytes, err := EncodePEMECKey(cs.leKey)
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
		return nil, SecretGetErrorWrap(err)
	}
	if sec == nil {
		return nil, &SecretGetError{Inner: fmt.Errorf("secret not found: %v", path), NotFound: true}
	}
	if sec.Data == nil {
		return nil, &SecretGetError{Inner: fmt.Errorf("secret not found: secret at %v is deleted", path), NotFound: true}
	}
	return sec, nil
}

func (cs CertStorage) putSecret(path string, data map[string]interface{}) error {
	_, err := cs.vcli.KVv2(cs.mount).Put(context.Background(), path, data)
	if err != nil {
		return fmt.Errorf("error setting secret at %v: %w", path, err)
	}
	return nil
}

func (cs CertStorage) patchSecret(path string, newData map[string]interface{}) error {
	_, err := cs.vcli.KVv2(cs.mount).Patch(context.Background(), path, newData)
	if err != nil {
		return fmt.Errorf("error updating secret at %v: %w", path, err)
	}
	return nil
}

// List lists the contents in a kv2 secret engine at the specified prefix
// The prefix should be given as used in the CLI, this function takes care
// of mapping it to the correct API path.
func (cs CertStorage) List(prefix string) []string {
	var contents []string
	secs, err := cs.vcli.Logical().List(cs.mount + "/metadata/" + prefix)
	if err == nil && secs != nil {
		if keys, ok := secs.Data["keys"]; ok {
			if keyList, ok := keys.([]interface{}); ok {
				for _, v := range keyList {
					if sv, ok := v.(string); ok {
						contents = append(contents, sv)
					}
				}
			}
		}
	}
	return contents
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

	certList, err = DecodeCerts([]byte(certPEM), certList)
	if err != nil {
		return nil, fmt.Errorf("error decoding certs at %v: %w", path, err)
	}

	return certList, nil
}

func (cs CertStorage) PutCerts(path string, certPEM []byte, keyPem []byte) error {
	return cs.putSecret(path, map[string]interface{}{
		"cert": string(certPEM),
		"key":  string(keyPem),
	})
}
