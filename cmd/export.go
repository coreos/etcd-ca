package cmd

import (
	"archive/tar"
	"fmt"
	"os"

	"github.com/coreos/etcd-ca/third_party/github.com/codegangsta/cli"

	"github.com/coreos/etcd-ca/depot"
)

func NewExportCommand() cli.Command {
	return cli.Command{
		Name:        "export",
		Usage:       "Export host request and key",
		Description: "Package up a certificate and key for export to a server.",
		Action:      newExportAction,
	}
}

func newExportAction(c *cli.Context) {
	if len(c.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "One host name must be provided.")
		os.Exit(1)
	}
	name := c.Args()[0]

	crtFi, crtBytes, err := d.GetFile(depot.HostCrtTag(name))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Got certificate fileinfo error:", err)
		os.Exit(1)
	}

	keyFi, keyBytes, err := d.GetFile(depot.HostPrivKeyTag(name))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Got key fileinfo error:", err)
		os.Exit(1)
	}

	w := tar.NewWriter(os.Stdout)
	defer w.Close()
	if err = outputTarFile(crtFi, crtBytes, w); err != nil {
		fmt.Fprintln(os.Stderr, "Saved certificate error:", err)
		os.Exit(1)
	}
	if err = outputTarFile(keyFi, keyBytes, w); err != nil {
		fmt.Fprintln(os.Stderr, "Saved key error:", err)
		os.Exit(1)
	}
}

func outputTarFile(fi os.FileInfo, data []byte, out *tar.Writer) error {
	header, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}

	if err = out.WriteHeader(header); err != nil {
		return err
	}

	if _, err = out.Write(data); err != nil {
		return err
	}

	return nil
}
