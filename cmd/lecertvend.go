package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"lecertvend"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
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
	cs      lecertvend.CertStorage
	cvm     lecertvend.CertVendingMachine
	zone    string
	Stagger bool
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
	rand.Seed(time.Now().UnixNano())

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
		zone, err := lecertvend.ZoneFromPrefix(prefix)
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
		var wg *sync.WaitGroup = new(sync.WaitGroup)
		err = Renew(wg, cs, mindays, prefix, staging)
		if err != nil {
			fmt.Printf("renew error: %v", err)
			os.Exit(1)
		}
		fmt.Println("renewals started, waiting for completion...")
		wg.Wait()
		fmt.Println("renewals complete.")
	}

	os.Exit(0)
}

func (z ZoneCertIssuer) IssueAndStore(namesRaw string, secPath string) error {
	if z.Stagger {
		wait := time.Duration(rand.Intn(6)) * time.Second
		fmt.Printf("waiting %v before issuing %v\n", wait, secPath)
		time.Sleep(wait)
	}
	names := strings.Split(namesRaw, ",")
	ckp, err := z.cvm.VendCert(names)
	if err != nil {
		return fmt.Errorf("error vending cert: %w", err)
	}
	z.cs.PutCerts(secPath, ckp.CertChainPEM, ckp.PrivKeyPEM)
	fmt.Printf("Newly issued certificate and key written to %v\n", secPath)
	return nil
}

func (z ZoneCertIssuer) IssueWaiter(namesRaw string, secPath string, wg *sync.WaitGroup) {
	err := z.IssueAndStore(namesRaw, secPath)
	if err != nil {
		fmt.Printf("error issuing cert with names %v, zone %v, and secret path %v: %v",
			namesRaw, z.zone, secPath, err.Error())
	}
	wg.Done()
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
			namesFromCert, err := lecertvend.NamesFromCert(certs[0], z.zone)
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
		return z.IssueAndStore(namesRaw, secPath)
	}
	return nil
}

func Renew(wg *sync.WaitGroup, cs lecertvend.CertStorage, mindays int, prefix string, staging bool) error {
	fmt.Printf("Renewing certs in prefix %v if less than %v days validity remain.\n", prefix, mindays)
	// We may have been given an org-level prefix, which contains prefixes that are zones
	// and contain cert secrets.
	// Try to get a zone name from this prefix. If that fails, do NOT look for certs in the
	// secrets within this prefix.
	// If we got a zone name, then treat secrets in this prefix as though they should have
	// renewable certs in them.
	// In any case, when we encounter a "folder", traverse into it looking for certs.
	zone, err := lecertvend.ZoneFromPrefix(prefix)
	var zci ZoneCertIssuer
	if err != nil {
		fmt.Printf("%v does not end in zone, looking for zones within...\n", prefix)
	}
	if len(zone) > 0 {
		zci, err = NewZoneCertIssuer(zone, cs, staging)
		zci.Stagger = true
		if err != nil {
			return err
		}
	}
	// For each entry at this prefix, traverse if it is a folder otherwise attempt
	// to renew a cert if len(zone) > 0, indicating this prefix should have certs in it
	for _, s := range cs.List(prefix) {
		if strings.HasSuffix(s, "/") { // is folder
			nextPrefix := prefix + "/" + s[0:len(s)-1]
			err = Renew(wg, cs, mindays, nextPrefix, staging)
			if err != nil {
				fmt.Printf("error traversing into %v: %v", nextPrefix, err)
			}
		} else { // is secret
			if len(zone) > 0 {
				secPath := prefix + "/" + s
				certs, err := cs.GetCerts(secPath)
				if err != nil {
					if sge := new(lecertvend.SecretGetError); errors.As(err, &sge) && sge.NotFound {
						fmt.Printf("secret %v is deleted\n", secPath)
					} else {
						fmt.Printf("failed to read certs from secret %v: %v\n", secPath, err)
					}
					continue
				}
				if len(certs) == 0 {
					fmt.Printf("certs was empty for secret %v\n", secPath)
					continue
				}
				namesRaw, err := lecertvend.NamesFromCert(certs[0], zone)
				if err != nil {
					fmt.Printf("error extracting names from cert in secret %v: %v\n", secPath, err)
					continue
				}
				remDays := lecertvend.CertValidDaysRemaining(certs[0])
				if remDays >= mindays {
					fmt.Printf("cert in secret %v has %v days of validity remaining, taking no action.\n", secPath, remDays)
					continue
				}
				// ISSUE - at this point we have a cert that needs renewal
				// Use WaitGroup here so multiple issuances that are waiting for DNS propagation
				// are waiting together and not in sequence
				wg.Add(1)
				go zci.IssueWaiter(namesRaw, secPath, wg)
			} else {
				fmt.Printf("ignoring secret %v in non-zone prefix %v\n", s, prefix)
			}
		}
	}
	return nil
}
