package pkix

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

const (
	certificatePEMBlockType = "CERTIFICATE"
)

type Certificate struct {
	// derBytes is always set for valid Certificate
	derBytes []byte

	pemBlock *pem.Block

	crt *x509.Certificate
}

// NewCertificateFromDER inits Certificate from DER-format bytes
func NewCertificateFromDER(derBytes []byte) *Certificate {
	return &Certificate{derBytes: derBytes}
}

// NewCertificateFromDER inits Certificate from PEM-format bytes
// data should contain at most one certificate
func NewCertificateFromPEM(data []byte) (c *Certificate, err error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		err = errors.New("cannot find the next PEM formatted block")
		return
	}
	if pemBlock.Type != certificatePEMBlockType || len(pemBlock.Headers) != 0 {
		err = errors.New("unmatched type or headers")
		return
	}
	c = &Certificate{derBytes: pemBlock.Bytes, pemBlock: pemBlock}
	return
}

// build crt field if needed
func (c *Certificate) buildX509Certificate() error {
	if c.crt != nil {
		return nil
	}

	crts, err := x509.ParseCertificates(c.derBytes)
	if err != nil {
		return err
	}
	if len(crts) != 1 {
		return errors.New("unsupported multiple certificates in a block")
	}
	c.crt = crts[0]
	return nil
}

// GetRawCrt gets crypto/x509-format Certificate
func (c *Certificate) GetRawCrt() (*x509.Certificate, error) {
	if err := c.buildX509Certificate(); err != nil {
		return nil, err
	}
	return c.crt, nil
}

// CheckAuthority checks the authority of certificate against itself.
// It only ensures that certificate is self-explanatory, and
// cannot promise the validity and security.
func (c *Certificate) CheckAuthority() error {
	if err := c.buildX509Certificate(); err != nil {
		return err
	}
	return c.crt.CheckSignatureFrom(c.crt)
}

// VerifyHost verifies the host certificate using host name.
// Only certificate of authority could call this function successfully.
// Current implementation allows one CA and direct hosts only,
// so the organization is always this:
//         CA
//  host1 host2 host3
func (c *Certificate) VerifyHost(hostCert *Certificate, name string) error {
	if err := c.CheckAuthority(); err != nil {
		return err
	}

	roots := x509.NewCertPool()
	roots.AddCert(c.crt)

	verifyOpts := x509.VerifyOptions{
		DNSName: name,
		// no intermediates are allowed for now
		Intermediates: nil,
		Roots:         roots,
		// if zero, the current time is used
		CurrentTime: time.Now(),
		// An empty list means ExtKeyUsageServerAuth.
		KeyUsages: nil,
	}

	chains, err := hostCert.crt.Verify(verifyOpts)
	if err != nil {
		return err
	}
	if len(chains) != 1 {
		err = errors.New("internal error: verify chain number != 1")
		return err
	}
	return nil
}

func (c *Certificate) buildPEM() {
	if c.pemBlock != nil {
		return
	}

	c.pemBlock = &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   c.derBytes,
	}
}

// Export returns PEM-format bytes
func (c *Certificate) Export() ([]byte, error) {
	c.buildPEM()

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, c.pemBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
