package lecertvend

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/api"
)

func DecodePEMECKey(pemData []byte) (*ecdsa.PrivateKey, error) {
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

func EncodePEMECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	x509bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling key: %v", err)
	}
	b := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509bytes,
	}
	return pem.EncodeToMemory(&b), nil
}

func getCertPEMString(secret *api.KVSecret) (string, error) {
	certPEM, ok := secret.Data["cert"].(string)
	if !ok {
		return "", fmt.Errorf("secret \"cert\" key is missing or not a string")
	}
	if len(certPEM) == 0 {
		return "", fmt.Errorf("secret \"cert\" key is empty")
	}

	return certPEM, nil
}

func DecodeCerts(pemBytes []byte, certList []*x509.Certificate) ([]*x509.Certificate, error) {
	p, rest := pem.Decode(pemBytes)
	if p == nil {
		return certList, nil
	} else {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %v", err)
		}
		return DecodeCerts(rest, append(certList, cert))
	}
}
