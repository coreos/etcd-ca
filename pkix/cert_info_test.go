package pkix

import (
	"encoding/base64"
	"testing"
)

const (
	serialNumber = 10
	infoBASE64   = "MTA="
)

func TestCertificateAuthorityInfo(t *testing.T) {
	i := NewCertificateAuthorityInfo(serialNumber)

	i.IncSerialNumber()
	if i.SerialNumber.Uint64() != serialNumber+1 {
		t.Fatal("Failed incrementing serial number")
	}
}

func TestCertificateAuthorityInfoFromJSON(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(infoBASE64)
	if err != nil {
		t.Fatal("Failed decoding base64 string:", err)
	}

	i, err := NewCertificateAuthorityInfoFromJSON(data)
	if err != nil {
		t.Fatal("Failed init CertificateAuthorityInfo:", err)
	}

	if i.SerialNumber.Uint64() != serialNumber {
		t.Fatal("Failed getting correct serial number")
	}

	b, err := i.Export()
	if err != nil {
		t.Fatal("Failed exporting info:", err)
	}
	if base64.StdEncoding.EncodeToString(b) != infoBASE64 {
		t.Fatal("Failed exporting correct info")
	}
}
