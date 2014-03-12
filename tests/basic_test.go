package tests

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

const (
	binPath  = "../bin/etcd-ca"
	depotDir = ".etcd-ca-test"
	hostname = "host1"
)

func run(command string, args ...string) (string, string, error) {
	var stdoutBytes, stderrBytes bytes.Buffer
	args = append([]string{"--depot-path", depotDir}, args...)
	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdoutBytes
	cmd.Stderr = &stderrBytes
	err := cmd.Run()
	return stdoutBytes.String(), stderrBytes.String(), err
}

func TestVersion(t *testing.T) {
	stdout, stderr, err := run(binPath, "--version")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if !strings.Contains(stdout, "version") {
		t.Fatalf("Received unexpected stdout: %v", stdout)
	}
}
