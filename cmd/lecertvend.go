package main

import (
	_ "embed"
	"flag"
	"fmt"
	"lecertvend"
	"os"
	"strings"
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

func main() {
	// Invocation Modes:
	// vend  - Issue a certificate for a particular DNS name, or renew it
	// if it already exists and is aging
	// renew - Examine each certificate in a vault prefix and renew it if it is aging

	var vend, renew bool
	var mindays int
	var mount, prefix, cert, namesRaw string
	flag.BoolVar(&vend, "vend", false, "Vend a single certificate")
	flag.BoolVar(&renew, "renew", false, "Renew all certs in a prefix")
	flag.IntVar(&mindays, "mindays", 30, "Renew certs expiring in this many or fewer days")
	flag.StringVar(&mount, "mount", "", "Vault kv2 secret engine mount location")
	flag.StringVar(&prefix, "prefix", "", "Vault path prefix for DNS domain")
	flag.StringVar(&cert, "cert", "", "Vault secret name in which to store cert chain and key")
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
	if vend && cert == "" {
		exitWithUsage("ERROR: -cert must be specified with -vend")
	}
	if vend && namesRaw == "" {
		exitWithUsage("ERROR: -names must be specified with -vend")
	}

	// Strip leading and trailing slashes off prefix
	strings.Trim(prefix, "/")

	certStorage, err := lecertvend.NewCertStorage(mount, prefix)
	if err != nil {
		exitWithUsage(err.Error())
	}

	secretPath := "lecertmgmt/gurp/omt.cx/auth1"
	certList, err := certStorage.GetCerts(secretPath)

	fmt.Printf("Subject: %v\n", certList[0].Subject.CommonName)
	notAfter := certList[0].NotAfter
	remaining := notAfter.Sub(time.Now())
	remDays := int(remaining.Hours() / 24)
	fmt.Printf("Cert remaining days: %v\n", remDays)

	lecertvend.DeleteTXT(certStorage.CFToken(), "omt.cx.", "apitest")
}
