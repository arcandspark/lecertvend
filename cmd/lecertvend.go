package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"log"
	"time"
)

func main() {
	fmt.Println("Cert vending machine")
	cfg := vault.DefaultConfig()
	vcli, err := vault.NewClient(cfg)
	if err != nil {
		log.Fatalf("error creating vault client: %v\n", err)
	}

	secretPath := "lecertmgmt/certs/auth1.omt.cx"
	secret, err := vcli.KVv2("secret").Get(
		context.Background(), secretPath)
	if err != nil {
		log.Fatalf("error getting %v: %v\n", secretPath, err)
	}

	certData, ok := secret.Data["cert"].(string)
	if !ok {
		log.Fatalf("cert property was not present and a string\n")
	}

	der, _ := pem.Decode([]byte(certData))
	if der == nil {
		log.Fatalf("could not decode PEM data from vault\n")
	}

	cert, err := x509.ParseCertificates(der.Bytes)
	if err != nil {
		log.Fatalf("failed to parse cert data: %v", err)
	}

	fmt.Printf("Subject: %v\n", cert[0].Subject.CommonName)
	notAfter := cert[0].NotAfter
	remaining := notAfter.Sub(time.Now())
	remDays := int(remaining.Hours() / 24)
	fmt.Printf("Cert remaining days: %v\n", remDays)

	secs, err := vcli.Logical().List("secret/metadata/omtweb/certs")
	if err != nil {
		log.Fatalf("error listing secrets metadata: %v\n")
	}

	for _, v := range secs.Data["keys"].([]interface{}) {
		sv, ok := v.(string)
		if ok {
			fmt.Printf("Secret: %v\n", sv)
		}
	}
}
