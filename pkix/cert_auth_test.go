package pkix

import (
	"testing"
	"time"
)

func TestCreateCertificateAuthority(t *testing.T) {
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	crt, info, err := CreateCertificateAuthority(key)
	if err != nil {
		t.Fatal("Failed creating certificate authority:", err)
	}
	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}

	if err = rawCrt.CheckSignatureFrom(rawCrt); err != nil {
		t.Fatal("Failed to check signature:", err)
	}

	if rawCrt.Subject.OrganizationalUnit[0] != authHostname {
		t.Fatal("Failed to verify hostname:", err)
	}

	if !time.Now().After(rawCrt.NotBefore) {
		t.Fatal("Failed to be after NotBefore")
	}

	if !time.Now().Before(rawCrt.NotAfter) {
		t.Fatal("Failed to be before NotAfter")
	}

	if info.SerialNumber.Uint64() != authStartSerialNumber {
		t.Fatal("Failed to set serial number")
	}
}
