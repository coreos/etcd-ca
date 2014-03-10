package pkix

import (
	"bytes"
	"testing"
)

const (
	certAuthPEM = `-----BEGIN CERTIFICATE-----
MIIB9zCCAWKgAwIBAgIBATALBgkqhkiG9w0BAQUwMTEMMAoGA1UEBhMDVVNBMRQw
EgYDVQQKEwtDb3JlT1MgSW5jLjELMAkGA1UEAxMCQ0EwHhcNMTQwMzA5MTgzMzQx
WhcNMjQwMzA5MTkzMzQxWjAxMQwwCgYDVQQGEwNVU0ExFDASBgNVBAoTC0NvcmVP
UyBJbmMuMQswCQYDVQQDEwJDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
ptSfk77PDDWYiNholqgPyQwtnf7hmoFGEqiA4Cu0u+LW7vLqkysaXHUVjQH/ditJ
FPlvwsllgPbgCF9bUzrCbXbrV2xjIhairyOGFSrLGBZMIB91xHXPlFhy2U+4Piio
bisrv2InHvPTyyZqVbqLDhF8DmVMIZI/UCOKtCMSrN8CAwEAAaMjMCEwDgYDVR0P
AQH/BAQDAgAEMA8GA1UdEwEB/wQFMAMBAf8wCwYJKoZIhvcNAQEFA4GBAHKzf9iH
fKUdWUz5Ue8a1yRRTu5EuGK3pz22x6udcIYH6KFBPVfj5lSbbE3NirE7TKWvF2on
SCP/620bWJMxqNAYdwpiyGibsiUlueWB/3aavoq10MIHA6MBxw/wrsoLPns9f7dP
+ddM40NjuI1tvX6SnUwuahONdvUJDxqVR+AM
-----END CERTIFICATE-----
`
	badCertAuthPEM = `-----BEGIN CERTIFICATE-----
MIIB9zCCAWKgAwIBAgIBATALBgkqhkiG9w0BAQUwMTEMMAoGA1UEBhMDVVNBMRQw
EgYAVQQKEwtDb3JlT1MgSW5jLjELMAkGA1UEAxMCQ0EwHhcNMTQwMzA5MjE1NDI5
WhcNMjQwMzA5MjI1NDI5WjAxMQwwCgYDVQQGEwNVU0ExFDASBgNVBAoTC0NvcmVP
UyBJbmMuMQswCQYDVQQDEwJDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
xLZYiSaYRWC90r/W+3cVFI6NnWfEo9Wrbn/PsJRz+Nn1NURuLpYWrMSZa1ihipVr
bPY9Xi8Xo5YCll2z9RcWoVp0ASU1VxctXKWbsk/lqnAKDX+/lTW4iKERUF67NOlR
GFtBzq7iVPQT7qNYCMu3CRG/4cTuOcCglH/xE9HdgdcCAwEAAaMjMCEwDgYDVR0P
AQH/BAQDAgAEMA8GA1UdEwEB/wQFMAMBAf8wCwYJKoZIhvcNAQEFA4GBAL129Vc3
lcfYfSfI2fMgkG3hc2Yhtu/SJ7wRFqlrNBM9lnNJnYMF+fAWv6u8xix8OWfYs38U
BB6sTriDpe5oo2H0o7Pf5ACE3IIy2Cf2+HAmNClYrdlwNYfP7aUazbEhuzPcvJYA
zPNy61oRnsETV77BH+JQ7j4E+pAJ5MHpKUcq
-----END CERTIFICATE-----
`
	wrongCertAuthPEM = `-----BEGIN WRONG CERTIFICATE-----
MIIB9zCCAWKgAwIBAgIBATALBgkqhkiG9w0BAQUwMTEMMAoGA1UEBhMDVVNBMRQw
EgYDVQQKEwtDb3JlT1MgSW5jLjELMAkGA1UEAxMCQ0EwHhcNMTQwMzA5MTgzMzQx
WhcNMjQwMzA5MTkzMzQxWjAxMQwwCgYDVQQGEwNVU0ExFDASBgNVBAoTC0NvcmVP
UyBJbmMuMQswCQYDVQQDEwJDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
ptSfk77PDDWYiNholqgPyQwtnf7hmoFGEqiA4Cu0u+LW7vLqkysaXHUVjQH/ditJ
FPlvwsllgPbgCF9bUzrCbXbrV2xjIhairyOGFSrLGBZMIB91xHXPlFhy2U+4Piio
bisrv2InHvPTyyZqVbqLDhF8DmVMIZI/UCOKtCMSrN8CAwEAAaMjMCEwDgYDVR0P
AQH/BAQDAgAEMA8GA1UdEwEB/wQFMAMBAf8wCwYJKoZIhvcNAQEFA4GBAHKzf9iH
fKUdWUz5Ue8a1yRRTu5EuGK3pz22x6udcIYH6KFBPVfj5lSbbE3NirE7TKWvF2on
SCP/620bWJMxqNAYdwpiyGibsiUlueWB/3aavoq10MIHA6MBxw/wrsoLPns9f7dP
+ddM40NjuI1tvX6SnUwuahONdvUJDxqVR+AM
-----END WRONG CERTIFICATE-----
`
)

func TestCertificateAuthority(t *testing.T) {
	crt, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	if err = crt.CheckAuthority(); err != nil {
		t.Fatal("Failed to check self-sign:", err)
	}

	if err = crt.VerifyHost(crt, authHostname); err != nil {
		t.Fatal("Failed to verify CA:", err)
	}
}

func TestWrongCertificate(t *testing.T) {
	if _, err := NewCertificateFromPEM([]byte("-")); err == nil {
		t.Fatal("Expect not to parse certificate from PEM:", err)
	}

	if _, err := NewCertificateFromPEM([]byte(wrongCertAuthPEM)); err == nil {
		t.Fatal("Expect not to parse certificate from PEM:", err)
	}
}

func TestBadCertificate(t *testing.T) {
	crt, err := NewCertificateFromPEM([]byte(badCertAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	if _, err = crt.GetRawCrt(); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if err = crt.CheckAuthority(); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if err = crt.VerifyHost(crt, authHostname); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	pemBytes, err := crt.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(badCertAuthPEM)) != 0 {
		t.Fatal(len(pemBytes), len(badCertAuthPEM))
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

// TestCertificateExport tests the ability to convert DER bytes into PEM bytes
func TestCertificateExport(t *testing.T) {
	crt, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	// remove the copy of PEM in crt
	crt.pemBlock = nil

	pemBytes, err := crt.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(certAuthPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}
