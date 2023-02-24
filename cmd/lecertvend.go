package main

import (
	"crypto/x509"
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

type ZoneCertIssuer struct {
	cs   lecertvend.CertStorage
	cvm  lecertvend.CertVendingMachine
	zone string
}

func NewZoneCertIssuer(zone string, cs lecertvend.CertStorage, staging bool) (ZoneCertIssuer, error) {
	var zci ZoneCertIssuer
	var err error
	zci.cs = cs
	zci.zone = zone

	zci.cvm, err = lecertvend.NewCertVendingMachine(zci.zone, zci.cs.Contact(),
		zci.cs.CFToken(), zci.cs.LEKey())
	if err != nil {
		return zci, fmt.Errorf("error creating CertVendingMachine: %w", err)
	}
	if staging {
		zci.cvm.ACMEEndpoint = lecertvend.LEStagingEndpoint
	}
	return zci, nil
}

func main() {
	// Invocation Modes:
	// vend  - Issue a certificate for a particular DNS name, or renew it
	// if it already exists and is aging
	// renew - Examine each certificate in a vault prefix and renew it if it is aging

	var vend, renew, staging bool
	var mindays int
	var mount, prefix, secret, namesRaw string
	flag.BoolVar(&vend, "vend", false, "Vend a single certificate")
	flag.BoolVar(&renew, "renew", false, "Renew all certs in a prefix")
	flag.BoolVar(&staging, "staging", false, "Use Let's Encrypt staging endpoint")
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

	// Initialize the cert storage, this will get Let's Encrypt and CloudFlare
	// creds from the Vault
	cs, err := lecertvend.NewCertStorage(mount, prefix)
	if err != nil {
		exitWithUsage(err.Error())
	}

	if vend {
		// VEND COMMAND
		zone, err := lecertvend.DomainFromPrefix(prefix)
		if err != nil {
			exitWithUsage(fmt.Sprintf("could not determine domain from -prefix: %v", prefix))
		}
		zci, err := NewZoneCertIssuer(zone, cs, staging)
		if err != nil {
			exitWithUsage(err.Error())
		}
		err = zci.Vend(mindays, prefix, secret, namesRaw)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else if renew {
		// RENEW COMMAND
	}

	os.Exit(0)
}

// Vend ensures that the secret at prefix/secret contains a certificate and private key,
// and that the certificate has at least mindays of validity.
//
// If there is a certificate at that secret path already, and it has >= mindays of validity,
// that cert will not be updated. Otherwise, a new cert will be issued with all of namesRaw
// as SANs on the new cert.
func (z ZoneCertIssuer) Vend(mindays int, prefix string, secret string, namesRaw string) error {
	fmt.Printf("Vending cert for %v.%v\n", namesRaw, z.zone)

	secPath := prefix + "/" + secret
	doIssue := false
	certs, err := z.cs.GetCerts(secPath)
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
				fmt.Printf("Cert at %v has %v days validity remaining.\n", secPath, remDays)
			}
			namesFromCert, err := lecertvend.NamesFromCert(certs[0], prefix)
			if err != nil {
				return fmt.Errorf("error getting DNS names from existing certificate at %v: %w", secPath, err)
			}
			if namesFromCert != namesRaw {
				fmt.Printf("Cert names '%v' does not exactly match -names '%v'\n", namesFromCert, namesRaw)
				fmt.Println("Issuing new certificate with requested names...")
				doIssue = true
			}
		}
	}

	if doIssue {
		names := strings.Split(namesRaw, ",")
		ckp, err := z.cvm.VendCert(names)
		if err != nil {
			return err
		}
		z.cs.PutCerts(secPath, ckp.CertChainPEM, ckp.PrivKeyPEM)
		fmt.Printf("Newly issued certificate and key written to %v\n", secPath)
	}
	return nil
}

func (z ZoneCertIssuer) Renew(mindays int, prefix string) error {
	fmt.Printf("Renewing certs in prefix %v if less than %v days validity remain.\n", prefix, mindays)
	return nil
}

func PrintCertInfo(cert *x509.Certificate, prefix string) {
	fmt.Printf("Subject CN: '%v'\n\n", cert.Subject.CommonName)
	fmt.Printf("Number of DNS names: %v\n", len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		fmt.Printf("DNS Name: %v\n", n)
	}
	nameList, err := lecertvend.NamesFromCert(cert, prefix)
	if err != nil {
		fmt.Printf("error creating nameList: %v\n", err)
	}
	fmt.Printf("nameList: '%v'\n", nameList)
}
