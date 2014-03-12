package pkix

import (
	"bytes"
	"testing"
	"time"
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
	certHostPEM = `-----BEGIN CERTIFICATE-----
MIICEzCCAX6gAwIBAgIBAjALBgkqhkiG9w0BAQUwMTEMMAoGA1UEBhMDVVNBMRQw
EgYDVQQKEwtDb3JlT1MgSW5jLjELMAkGA1UEAxMCQ0EwHhcNMTQwMzExMTkwOTMx
WhcNMjQwMzExMTkwOTMxWjAwMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2Qt
Y2ExDjAMBgNVBAMTBWhvc3QxMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr
YfUfmFfGtac16Ez9zwOBQggz70R/eOFnM3OAD9GFXaKzTOJJhZNa9iDLIT69zSeq
74i4rOaIH2Yt9LycWUuGgo3XK2AfDevnUIr0Af5rq/tOmBK708Q2FCTOnwD44eyS
DQVNwaIqj6dQV/cukrlCSR6o5t0nLp1QII/xPaBm+QIDAQABo0AwPjAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFEk719DRqeTH5K6Tag0r
ftDtdO4sMAsGCSqGSIb3DQEBBQOBgQBGNpubUIJClTFIOsZKbH/aikT3AIlNzK2t
XhBUZKJf8P4+gHiI461FGskSuTTkUiPeSzsH0FdDjwhIuUCRsUKES10VVHb1jqIu
S/nYTAI0ToSxKXBF2+M5umPOt65wjzcgnMj9QZgtm5AMJ9xmoZZMKBL9jAg7umiV
SJG3FlQNIA==
-----END CERTIFICATE-----`
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

	duration := crt.GetExpirationDuration()
	expireDate, _ := time.Parse("2006-Jan-02", "2024-Feb-03")
	if !time.Now().Add(duration).After(expireDate) {
		t.Fatal("Failed to get correct expiration")
	}

	pemBytes, err := crt.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(certAuthPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
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

	if _, err = crt.GetRawCertificate(); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if err = crt.CheckAuthority(); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if err = crt.VerifyHost(crt, authHostname); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if duration := crt.GetExpirationDuration(); duration.Hours() >= 0 {
		t.Fatal("Expect not to get positive duration")
	}

	pemBytes, err := crt.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(badCertAuthPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

func TestCertificateVerify(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	crtHost, err := NewCertificateFromPEM([]byte(certHostPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	if err = crtAuth.VerifyHost(crtHost, csrHostname); err != nil {
		t.Fatal("Verify certificate host from CA:", err)
	}
}
