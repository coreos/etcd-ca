package tests

import (
	"os/exec"
	"testing"
)

func TestRunnable(t *testing.T) {
	cmd := exec.Command("../bin/etcd-ca")
	_, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Received unexpected error: %v", err)
	}
}
