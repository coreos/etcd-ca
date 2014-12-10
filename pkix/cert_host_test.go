package pkix

import (
	"testing"
)

func TestCreateCertificateHost(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	csr, err := NewCertificateSigningRequestFromPEM([]byte(csrPEM))
	if err != nil {
		t.Fatal("Failed parsing certificate request from PEM:", err)
	}

	crt, err := CreateCertificateHost(crtAuth, NewCertificateAuthorityInfo(authStartSerialNumber), key, csr, 1)
	if err != nil {
		t.Fatal("Failed creating certificate for host:", err)
	}

	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}

	rawCrtAuth, err := crtAuth.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}
	if err = rawCrt.CheckSignatureFrom(rawCrtAuth); err != nil {
		t.Fatal("Failed to check signature:", err)
	}

	if err = rawCrt.VerifyHostname(csrIP); err != nil {
		t.Fatal("Failed to verify CommonName:", err)
	}

	if rawCrt.SerialNumber.Uint64() != authStartSerialNumber {
		t.Fatal("Expect serial number %v instead of %v", authStartSerialNumber, rawCrt.SerialNumber)
	}
}
