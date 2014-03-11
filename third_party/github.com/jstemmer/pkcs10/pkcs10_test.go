package pkcs10

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // required to test ECDSA signature generation
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestCreateCertificateSigningRequest(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %s", err)
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	tests := []struct {
		name string
		priv interface{}
	}{
		{"RSA", rsaPriv},
		{"ECDSA", ecdsaPriv},
	}

	for _, test := range tests {
		commonName := "test.example.com"
		template := CertificateSigningRequest{
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
			},
		}

		derBytes, err := CreateCertificateSigningRequest(rand.Reader, &template, test.priv)
		if err != nil {
			t.Fatalf("%s: failed to create certificate signing request: %s", test.name, err)
		}

		f, err := os.Create(fmt.Sprintf("/tmp/output-%s.csr", test.name))
		if err != nil {
			t.Fatalf("could not create output file: %s", err)
		}
		defer f.Close()

		block := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes}
		err = pem.Encode(f, block)
		if err != nil {
			t.Fatalf("could not write output to file: %s", err)
		}

		csr, err := ParseCertificateSigningRequest(derBytes)
		if err != nil {
			t.Fatalf("%s: failed to parse certificate signing request: %s", test.name, err)
		}

		if csr.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, csr.Subject.CommonName, commonName)
		}

		err = csr.CheckSignature()
		if err != nil {
			t.Errorf("%s: signature verification failed: %s", test.name, err)
		}
	}
}

func TestParseCertificateSigningRequest(t *testing.T) {
	block, _ := pem.Decode([]byte(csrNoAttrs))
	csr, err := ParseCertificateSigningRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Error parsing csr: %s", err)
	}

	if err = csr.CheckSignature(); err != nil {
		t.Fatalf("Signature check failed: %s", err)
	}

	if csr.Version != 0 {
		t.Errorf("Invalid CSR version. Got %d, want %d", csr.Version, 0)
	}

	expectedSubject := pkix.Name{
		Country:            []string{"NL"},
		Organization:       []string{"Σ Acme Co"},
		OrganizationalUnit: []string{"Unit"},
		Locality:           []string{"City"},
		Province:           []string{"Province"},
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "test.example.com",
		Names:              []pkix.AttributeTypeAndValue{},
	}

	if !reflect.DeepEqual(csr.Subject.Country, expectedSubject.Country) {
		t.Errorf("Incorrect country. Got %v, want %v", csr.Subject.Country, expectedSubject.Country)
	}

	if !reflect.DeepEqual(csr.Subject.Organization, expectedSubject.Organization) {
		t.Errorf("Incorrect organization. Got %v, want %v", csr.Subject.Organization, expectedSubject.Organization)
	}

	if !reflect.DeepEqual(csr.Subject.OrganizationalUnit, expectedSubject.OrganizationalUnit) {
		t.Errorf("Incorrect organizational unit. Got %v, want %v", csr.Subject.OrganizationalUnit, expectedSubject.OrganizationalUnit)
	}

	if !reflect.DeepEqual(csr.Subject.Locality, expectedSubject.Locality) {
		t.Errorf("Incorrect locality. Got %v, want %v", csr.Subject.Locality, expectedSubject.Locality)
	}

	if !reflect.DeepEqual(csr.Subject.Province, expectedSubject.Province) {
		t.Errorf("Incorrect province. Got %v, want %v", csr.Subject.Province, expectedSubject.Province)
	}

	if csr.Subject.CommonName != expectedSubject.CommonName {
		t.Errorf("Incorrect common name. Got %v, want %v", csr.Subject.CommonName, expectedSubject.CommonName)
	}
}

var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`

var pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA PRIVATE KEY-----
`

var csrNoAttrs = `-----BEGIN CERTIFICATE REQUEST-----
MIIBKDCB0wIBADBuMQswCQYDVQQGEwJOTDERMA8GA1UECAwIUHJvdmluY2UxDTAL
BgNVBAcMBENpdHkxEzARBgNVBAoMCs6jIEFjbWUgQ28xDTALBgNVBAsMBFVuaXQx
GTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBI
AkEAspkPScR9+ozUAK5qTRuKO2oTZCsj8osAO/uXeQremkzIK4sqgXR93sCLYpbl
OgjDMWh+8lxL9JNrocDmBB6dFQIDAQABoAAwDQYJKoZIhvcNAQEFBQADQQAZOqEg
pO+V1WGCGkBkGgmM2QlnrKaFYaRgYVlSEg7Tf+n9Wb8grcbQA8xo49z8qh2PbzgX
M7Ib4RDKnANBH0R+
-----END CERTIFICATE REQUEST-----
`
