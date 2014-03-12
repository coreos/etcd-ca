package cmd

import (
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
