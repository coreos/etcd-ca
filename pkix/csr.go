package pkix

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"

	"github.com/coreos/etcd-ca/third_party/github.com/jstemmer/pkcs10"
)

const (
	csrPEMBlockType = "CERTIFICATE REQUEST"
)

var (
	csrPkixName = pkix.Name{
		Country:            []string{"USA"},
		Organization:       []string{"etcd-ca"},
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "",
	}
)

func CreateCertificateSigningRequest(key *Key, name string) (*CertificateSigningRequest, error) {
	csrPkixName.CommonName = name
	csrTemplate := &pkcs10.CertificateSigningRequest{Subject: csrPkixName}

	csrBytes, err := pkcs10.CreateCertificateSigningRequest(rand.Reader, csrTemplate, key.Private)
	if err != nil {
		return nil, err
	}
	return NewCertificateSigningRequestFromDER(csrBytes), nil
}

type CertificateSigningRequest struct {
	// derBytes is always set for valid Certificate
	derBytes []byte

	cr *pkcs10.CertificateSigningRequest
}

// NewCertificateSigningRequestFromDER inits CertificateSigningRequest from DER-format bytes
func NewCertificateSigningRequestFromDER(derBytes []byte) *CertificateSigningRequest {
	return &CertificateSigningRequest{derBytes: derBytes}
}

// NewCertificateSigningRequestFromPEM inits CertificateSigningRequest from PEM-format bytes
// data should contain at most one certificate
func NewCertificateSigningRequestFromPEM(data []byte) (*CertificateSigningRequest, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != csrPEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}
	return &CertificateSigningRequest{derBytes: pemBlock.Bytes}, nil
}

// build cr field if needed
func (c *CertificateSigningRequest) buildPKCS10CertificateSigningRequest() error {
	if c.cr != nil {
		return nil
	}

	var err error
	c.cr, err = pkcs10.ParseCertificateSigningRequest(c.derBytes)
	if err != nil {
		return err
	}
	return nil
}

// GetRawCertificateSigningRequest returns a copy of this certificate request as an pkcs10.Certificate
func (c *CertificateSigningRequest) GetRawCertificateSigningRequest() (*pkcs10.CertificateSigningRequest, error) {
	if err := c.buildPKCS10CertificateSigningRequest(); err != nil {
		return nil, err
	}
	return c.cr, nil
}

// CheckSignature verifies that the signature is a valid signature
// using the public key in CertificateSigningRequest.
func (c *CertificateSigningRequest) CheckSignature() error {
	if err := c.buildPKCS10CertificateSigningRequest(); err != nil {
		return err
	}
	return c.cr.CheckSignature()
}

// Export returns PEM-format bytes
func (c *CertificateSigningRequest) Export() ([]byte, error) {
	pemBlock := &pem.Block{
		Type:    csrPEMBlockType,
		Headers: nil,
		Bytes:   c.derBytes,
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
