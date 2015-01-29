package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/codegangsta/cli"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/coreos/etcd-ca/depot"
)

var (
	d *depot.FileDepot
)

func InitDepot(path string) error {
	if d == nil {
		var err error
		if d, err = depot.NewFileDepot(path); err != nil {
			return err
		}
	}
	return nil
}

func createPassPhrase() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter passphrase (empty for no passphrase): ")
	pass1, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, "\nEnter same passphrase again: ")
	pass2, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)

	if bytes.Compare(pass1, pass2) != 0 {
		return nil, errors.New("Passphrases do not match.")
	}
	return pass1, nil
}

func askPassPhrase(name string) []byte {
	fmt.Fprintf(os.Stderr, "Enter passphrase for %v (empty for no passphrase): ", name)
	pass, _ := terminal.ReadPassword(syscall.Stdin)
	fmt.Fprintln(os.Stderr)
	return pass
}

func getPassPhrase(c *cli.Context, name string) []byte {
	if c.IsSet("passphrase") {
		return []byte(c.String("passphrase"))
	} else {
		return askPassPhrase(name)
	}
}
