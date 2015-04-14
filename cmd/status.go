// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/coreos/etcd-ca/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/coreos/etcd-ca/depot"
	"github.com/coreos/etcd-ca/pkix"
)

func NewStatusCommand() cli.Command {
	return cli.Command{
		Name:        "status",
		Usage:       "List the status",
		Description: "Get the status of all certificates.",
		Action:      newStatusAction,
	}
}

func printSignedStatusLine(crt *pkix.Certificate, name string) {
	duration := crt.GetExpirationDuration()
	hours := duration.Hours()
	days := hours / 24
	if days < 60 {
		fmt.Printf("%s: WARN (%.2f days until expiration)\n", name, days)
	} else {
		fmt.Printf("%s: OK (%.2f days until expiration)\n", name, days)
	}
}

func newStatusAction(c *cli.Context) {
	crtAuth, err := depot.GetCertificateAuthority(d)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CA certificate hasn't existed!")
	} else {
		printSignedStatusLine(crtAuth, "CA")
	}

	tags := d.List()
	for _, tag := range tags {
		name := depot.GetNameFromHostCrtTag(tag)
		if name == "" {
			continue
		}
		if !depot.CheckCertificateSigningRequest(d, name) {
			fmt.Fprintln(os.Stderr, "Certificate request hasn't existed!")
			continue
		}
		crt, err := depot.GetCertificateHost(d, name)
		if err != nil {
			fmt.Printf("%s: Unsigned\n", name)
			continue
		}
		printSignedStatusLine(crt, name)
	}
}
