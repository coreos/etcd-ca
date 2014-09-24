package cmd

import (
	"fmt"
	"os"

	"github.com/coreos/etcd-ca/third_party/github.com/codegangsta/cli"

	"github.com/coreos/etcd-ca/depot"
	"github.com/coreos/etcd-ca/pkix"
)

func NewInitCommand() cli.Command {
	return cli.Command{
		Name:        "init",
		Usage:       "Create Certificate Authority",
		Description: "Create Certificate Authority, including certificate, key and extra information file.",
		Flags: []cli.Flag{
			cli.StringFlag{"passphrase", "", "Passphrase to encrypt private-key PEM block"},
			cli.IntFlag{"key-bits", 4096, "Bit size of RSA keypair to generate"},
			cli.IntFlag{"years", 10, "How long until the CA certificate expires"},
			cli.StringFlag{"organization", "etcd-ca", "CA Certificate organization"},
			cli.StringFlag{"country", "USA", "CA Certificate country"},
		},
		Action: initAction,
	}
}

func initAction(c *cli.Context) {
	if depot.CheckCertificateAuthority(d) || depot.CheckCertificateAuthorityInfo(d) || depot.CheckPrivateKeyAuthority(d) {
		fmt.Fprintln(os.Stderr, "CA has existed!")
		os.Exit(1)
	}

	var passphrase []byte
	var err error
	if c.IsSet("passphrase") {
		passphrase = []byte(c.String("passphrase"))
	} else {
		passphrase, err = createPassPhrase()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	key, err := pkix.CreateRSAKey(c.Int("key-bits"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create RSA Key error:", err)
		os.Exit(1)
	} else {
		fmt.Println("Created ca/key")
	}

	crt, info, err := pkix.CreateCertificateAuthority(key, c.Int("years"), c.String("organization"), c.String("country"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate error:", err)
		os.Exit(1)
	} else {
		fmt.Println("Created ca/crt")
	}

	if err = depot.PutCertificateAuthority(d, crt); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate error:", err)
	}
	if err = depot.PutCertificateAuthorityInfo(d, info); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate info error:", err)
	}
	if err = depot.PutEncryptedPrivateKeyAuthority(d, key, passphrase); err != nil {
		fmt.Fprintln(os.Stderr, "Save key error:", err)
	}
}
