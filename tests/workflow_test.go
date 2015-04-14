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

package tests

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWorkflow runs etcd-ca in the normal workflow
// and traverses all commands
func TestWorkflow(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err := run(binPath, "init", "--passphrase", passphrase)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received insufficient create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "new-cert", "--passphrase", passphrase, hostname)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received insufficient create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, hostname)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 1 {
		t.Fatalf("Received insufficient create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "chain")
	if err != nil {
		t.Fatalf("Received unexpected error: %v", err)
	}
	if strings.Count(stdout, "CERTIFICATE") != 2 {
		t.Fatalf("Received insufficient CERTIFICATE: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "chain", hostname)
	if err != nil {
		t.Fatalf("Received unexpected error: %v", err)
	}
	if strings.Count(stdout, "CERTIFICATE") != 4 {
		t.Fatalf("Received insufficient CERTIFICATE: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "export", hostname)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	ioutil.WriteFile("1.tar", []byte(stdout), 0644)
	defer os.Remove("1.tar")

	err = exec.Command("tar", "xvf", "1.tar").Run()
	if err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	keyFile := fmt.Sprintf("%v.key", hostname)
	crtFile := fmt.Sprintf("%v.crt", hostname)
	defer os.Remove(keyFile)
	defer os.Remove(crtFile)
	if _, err = os.Stat(keyFile); err != nil {
		t.Fatal("Failed stating", keyFile)
	}
	if _, err = os.Stat(crtFile); err != nil {
		t.Fatal("Failed stating", keyFile)
	}

	stdout, stderr, err = run(binPath, "status")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "expiration") != 2 {
		t.Fatalf("Received insufficient expiration: %v", stdout)
	}
}
