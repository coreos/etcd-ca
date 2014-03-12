package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"

	"github.com/coreos/etcd-ca/third_party/code.google.com/p/go.crypto/ssh/terminal"

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
	fmt.Print("Enter passphrase (empty for no passphrase): ")
	pass1, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Print("\nEnter same passphrase again: ")
	pass2, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Println()

	if bytes.Compare(pass1, pass2) != 0 {
		return nil, errors.New("Passphrases do not match.")
	}
	return pass1, nil
}

func askPassPhrase(name string) []byte {
	fmt.Println("Enter passphrase for %v (empty for no passphrase): ", name)
	pass, _ := terminal.ReadPassword(syscall.Stdin)
	fmt.Println()
	return pass
}
