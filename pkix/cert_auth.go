package pkix

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

const (
	// hostname used by CA certificate
	authHostname = "CA"
	// SerialNumber to start when signing certificate request
	authStartSerialNumber = 2
)

var (
	authPkixName = pkix.Name{
		Country:            nil,
		Organization:       nil,
		OrganizationalUnit: []string{authHostname},
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "",
	}
	// Build CA based on RFC5280
	authTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      authPkixName,
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore: time.Now().Add(-600).UTC(),
		NotAfter: time.Time{},
		// Used for certificate signing only
		KeyUsage: x509.KeyUsageCertSign,

		ExtKeyUsage:        nil,
		UnknownExtKeyUsage: nil,

		// activate CA
		BasicConstraintsValid: true,
		IsCA: true,
		// Not allow any non-self-issued intermediate CA
		MaxPathLen: 0,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}
)

// CreateCertificateAuthority creates Certificate Authority using existing key.
// CertificateAuthorityInfo returned is the extra infomation required by Certificate Authority.
func CreateCertificateAuthority(key *Key, years int, organization string, country string) (*Certificate, *CertificateAuthorityInfo, error) {
	subjectKeyId, err := GenerateSubjectKeyId(key.Public)
	if err != nil {
		return nil, nil, err
	}
	authTemplate.SubjectKeyId = subjectKeyId
	authTemplate.NotAfter = time.Now().AddDate(years, 0, 0).UTC()
	authTemplate.Subject.Country = []string{country}
	authTemplate.Subject.Organization = []string{organization}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, &authTemplate, key.Public, key.Private)
	if err != nil {
		return nil, nil, err
	}

	return NewCertificateFromDER(crtBytes), NewCertificateAuthorityInfo(authStartSerialNumber), nil
}
