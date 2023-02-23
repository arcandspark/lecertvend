package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"lecertvend"
	"os"
	"strings"
)

//go:embed usage.txt
var usage string

func exitWithUsage(msg string) {
	fmt.Println(usage)
	fmt.Println("")
	fmt.Println(msg)
	os.Exit(1)
}

type LECertVend struct {
	cs   lecertvend.CertStorage
	cvm  lecertvend.CertVendingMachine
	zone string
}

func main() {
	// Invocation Modes:
	// vend  - Issue a certificate for a particular DNS name, or renew it
	// if it already exists and is aging
	// renew - Examine each certificate in a vault prefix and renew it if it is aging

	var vend, renew bool
	var mindays int
	var mount, prefix, secret, namesRaw string
	flag.BoolVar(&vend, "vend", false, "Vend a single certificate")
	flag.BoolVar(&renew, "renew", false, "Renew all certs in a prefix")
	flag.IntVar(&mindays, "mindays", 30, "Renew certs expiring in this many or fewer days")
	flag.StringVar(&mount, "mount", "", "Vault kv2 secret engine mount location")
	flag.StringVar(&prefix, "prefix", "", "Vault path prefix for DNS domain")
	flag.StringVar(&secret, "secret", "", "Vault secret name in which to store cert chain and key")
	flag.StringVar(&namesRaw, "names", "", "Comma separated list of host names for which to gen a cert")
	flag.Parse()

	if vend == renew {
		exitWithUsage("ERROR: One and only one of -vend or -renew must be specified")
	}
	if mount == "" {
		exitWithUsage("ERROR: -mount must be specified")
	}
	if prefix == "" {
		exitWithUsage("ERROR: -prefix must be specified")
	}
	if vend && secret == "" {
		exitWithUsage("ERROR: -secret must be specified with -vend")
	}
	if vend && namesRaw == "" {
		exitWithUsage("ERROR: -names must be specified with -vend")
	}

	// Strip leading and trailing slashes off prefix
	strings.Trim(prefix, "/")

	var lecv LECertVend
	var err error
	lecv.cs, err = lecertvend.NewCertStorage(mount, prefix)
	if err != nil {
		exitWithUsage(err.Error())
	}
	lecv.zone, err = lecertvend.DomainFromPrefix(prefix)
	if err != nil {
		exitWithUsage(fmt.Sprintf("could not determine domain from -prefix: %v", prefix))
	}
	lecv.cvm, err = lecertvend.NewCertVendingMachine(lecv.zone, lecv.cs.Contact(),
		lecv.cs.CFToken(), lecv.cs.LEKey())
	if err != nil {
		exitWithUsage(fmt.Sprintf("error creating CertVendingMachine: %v", err))
	}

	if vend {
		err = lecv.Vend(mindays, prefix, secret, namesRaw)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	os.Exit(0)
}

// Vend ensures that the secret at prefix/secret contains a certificate and private key,
// and that the certificate has at least mindays of validity.
//
// If there is a certificate at that secret path already, and it has >= mindays of validity,
// that cert will not be updated. Otherwise, a new cert will be issued with all of namesRaw
// as SANs on the new cert.
//
// **WARNING**, This function does not check to see that the requested names match the SANs
// on an existing certificate. So, if the certificate exists and has >= mindays of
// validity, but the SANs on the existing cert do not match the requested names, no
// error will be indicated.
func (l LECertVend) Vend(mindays int, prefix string, secret string, namesRaw string) error {
	secPath := prefix + "/" + secret
	doIssue := false
	certs, err := l.cs.GetCerts(secPath)
	if err != nil {
		var sge *lecertvend.SecretGetError
		if errors.As(err, &sge) && sge.NotFound {
			fmt.Printf("No existing cert at %v, issuing new...\n", secPath)
			doIssue = true
		} else {
			return err
		}
	}

	if certs != nil {
		if len(certs) == 0 {
			fmt.Printf("Secret exists at %v but contained no certs, issuing new...\n", secPath)
			doIssue = true
		} else {
			remDays := lecertvend.CertValidDaysRemaining(certs[0])
			if remDays < mindays {
				fmt.Printf("Cert at %v has %v days validity remaining, less than requested %v, issuing new...\n",
					secPath, remDays, mindays)
				doIssue = true
			} else {
				fmt.Printf("Cert at %v has %v days validity remaining, taking no action.\n", secPath, remDays)
			}
		}
	}

	if doIssue {
		names := strings.Split(namesRaw, ",")
		ckp, err := l.cvm.VendCert(names)
		if err != nil {
			return err
		}
		l.cs.PutCerts(secPath, ckp.CertChainPEM, ckp.PrivKeyPEM)
		fmt.Printf("Newly issued certificate and key written to %v\n", secPath)
	}
	return nil
}
