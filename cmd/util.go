package cmd

import (
	"errors"
	"fmt"

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
	var pass1, pass2 string
	fmt.Print("Enter passphrase (empty for no passphrase): ")
	fmt.Scanln(&pass1)
	fmt.Print("Enter same passphrase again: ")
	fmt.Scanln(&pass2)
	if pass1 != pass2 {
		return nil, errors.New("Passphrases do not match.")
	}
	return []byte(pass1), nil
}

func askPassPhrase(name string) []byte {
	var pass string
	fmt.Printf("Enter passphrase for %v (empty for no passphrase): ", name)
	fmt.Scanln(&pass)
	return []byte(pass)
}
