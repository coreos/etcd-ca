package pkix

import (
	"bytes"
	"testing"
)

const (
	csrHostname = "host1"
	csrPEM      = `-----BEGIN CERTIFICATE REQUEST-----
MIIBazCB1wIBADAwMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExDjAM
BgNVBAMTBWhvc3QxMIGdMAsGCSqGSIb3DQEBAQOBjQAwgYkCgYEAq2H1H5hXxrWn
NehM/c8DgUIIM+9Ef3jhZzNzgA/RhV2is0ziSYWTWvYgyyE+vc0nqu+IuKzmiB9m
LfS8nFlLhoKN1ytgHw3r51CK9AH+a6v7TpgSu9PENhQkzp8A+OHskg0FTcGiKo+n
UFf3LpK5QkkeqObdJy6dUCCP8T2gZvkCAwEAAaAAMAsGCSqGSIb3DQEBBQOBgQB/
pVIq3RhTKAzrqNF2NHktbbwh/1sTwOKfvBQC9hPhN6b/T3/7B8KmK99lXrBrlpSG
HwnD01nB/3/PBwqSMcmFLOcUGsuLp1Eh5APmlm6KQpnK6JAnYht/3De633PVQVZF
RlbHINSG7/jj/IDoXUmy8N4EczbAM2JaT6YBsEGPtw==
-----END CERTIFICATE REQUEST-----
`
	wrongCSRPEM = `-----BEGIN WRONG CERTIFICATE REQUEST-----
MIIBazCB1wIBADAwMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExDjAM
BgNVBAMTBWhvc3QxMIGdMAsGCSqGSIb3DQEBAQOBjQAwgYkCgYEAq2H1H5hXxrWn
NehM/c8DgUIIM+9Ef3jhZzNzgA/RhV2is0ziSYWTWvYgyyE+vc0nqu+IuKzmiB9m
LfS8nFlLhoKN1ytgHw3r51CK9AH+a6v7TpgSu9PENhQkzp8A+OHskg0FTcGiKo+n
UFf3LpK5QkkeqObdJy6dUCCP8T2gZvkCAwEAAaAAMAsGCSqGSIb3DQEBBQOBgQB/
pVIq3RhTKAzrqNF2NHktbbwh/1sTwOKfvBQC9hPhN6b/T3/7B8KmK99lXrBrlpSG
HwnD01nB/3/PBwqSMcmFLOcUGsuLp1Eh5APmlm6KQpnK6JAnYht/3De633PVQVZF
RlbHINSG7/jj/IDoXUmy8N4EczbAM2JaT6YBsEGPtw==
-----END WRONG CERTIFICATE REQUEST-----
`
	badCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIBazCB1wIBADAwMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExDjAM
NehM/c8DgUIIM+9Ef3jhZzNzgA/RhV2is0ziSYWTWvYgyyE+vc0nqu+IuKzmiB9m
UFf3LpK5QkkeqObdJy6dUCCP8T2gZvkCAwEAAaAAMAsGCSqGSIb3DQEBBQOBgQB/
pVIq3RhTKAzrqNF2NHktbbwh/1sTwOKfvBQC9hPhN6b/T3/7B8KmK99lXrBrlpSG
HwnD01nB/3/PBwqSMcmFLOcUGsuLp1Eh5APmlm6KQpnK6JAnYht/3De633PVQVZF
RlbHINSG7/jj/IDoXUmy8N4EczbAM2JaT6YBsEGPtw==
-----END CERTIFICATE REQUEST-----
`
)

func TestCreateCertificateSigningRequest(t *testing.T) {
	key, err := CreateRSAKey()
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	csr, err := CreateCertificateSigningRequest(key, csrHostname)
	if err != nil {
		t.Fatal("Failed creating certificate request:", err)
	}

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		t.Fatal("Failed getting raw certificate request:", err)
	}

	if err = rawCsr.CheckSignature(); err != nil {
		t.Fatal("Failed cheching signature in certificate request:", err)
	}

	if csrHostname != rawCsr.Subject.CommonName {
		t.Fatalf("Expect hostname to be %v instead of %v", csrHostname, rawCsr.Subject.CommonName)
	}
}

func TestCertificateSigningRequest(t *testing.T) {
	csr, err := NewCertificateSigningRequestFromPEM([]byte(csrPEM))
	if err != nil {
		t.Fatal("Failed parsing certificate request from PEM:", err)
	}

	if err = csr.CheckSignature(); err != nil {
		t.Fatal("Failed checking signature:", err)
	}

	pemBytes, err := csr.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(csrPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

func TestWrongCertificateSigningRequest(t *testing.T) {
	if _, err := NewCertificateSigningRequestFromPEM([]byte("-")); err == nil {
		t.Fatal("Expect not to parse from PEM:", err)
	}

	if _, err := NewCertificateSigningRequestFromPEM([]byte(wrongCSRPEM)); err == nil {
		t.Fatal("Expect not to parse from PEM:", err)
	}
}

func TestBadCertificateSigningRequest(t *testing.T) {
	csr, err := NewCertificateSigningRequestFromPEM([]byte(badCSRPEM))
	if err != nil {
		t.Fatal("Failed to parse from PEM:", err)
	}

	if _, err = csr.GetRawCertificateSigningRequest(); err == nil {
		t.Fatal("Expect not to get pkcs10.CertificateSigningRequest")
	}

	if err = csr.CheckSignature(); err == nil {
		t.Fatal("Expect not to get pkcs10.CertificateSigningRequest")
	}
}
