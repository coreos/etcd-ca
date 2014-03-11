// Package pkcs10 parses and creates PKCS#10 certificate signing requests, as
// specified in RFC 2986.
package pkcs10

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

type certificateSigningRequest struct {
	Raw                      asn1.RawContent
	CertificationRequestInfo certificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	SignatureValue           asn1.BitString
}

type certificationRequestInfo struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	SubjectPKInfo publicKeyInfo
	Attributes    []Attribute `asn1:"tag:0"`
}

type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// CertificateSigningRequest represents a PKCS#10 CSR.
type CertificateSigningRequest struct {
	Raw                         []byte
	RawCertificationRequestInfo []byte
	RawSubject                  []byte
	RawSubjectPublicKeyInfo     []byte

	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm

	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	PublicKey          interface{}

	Version int
	Subject pkix.Name
}

// ParseCertificateSigningRequest parses a certificate signing request from the
// given ASN.1 DER data.
func ParseCertificateSigningRequest(asn1Data []byte) (*CertificateSigningRequest, error) {
	var csr certificateSigningRequest
	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateSigningRequest(&csr)
}

// CheckSignature verifies that the signature on c is a valid signature using
// the public key in c.
func (c *CertificateSigningRequest) CheckSignature() (err error) {
	var hashType crypto.Hash

	switch c.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		return x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(c.RawCertificationRequestInfo)
	digest := h.Sum(nil)

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, c.Signature)
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(c.Signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("crypto/x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("crypto/x509: ECDSA verification failure")
		}
		return
	}
	return x509.ErrUnsupportedAlgorithm
}

func parseCertificateSigningRequest(in *certificateSigningRequest) (*CertificateSigningRequest, error) {
	out := new(CertificateSigningRequest)
	out.Raw = in.Raw
	out.RawCertificationRequestInfo = in.CertificationRequestInfo.Raw
	out.RawSubject = in.CertificationRequestInfo.Subject.FullBytes
	out.RawSubjectPublicKeyInfo = in.CertificationRequestInfo.SubjectPKInfo.Raw

	out.Signature = in.SignatureValue.RightAlign()
	out.SignatureAlgorithm = getSignatureAlgorithmFromOID(in.SignatureAlgorithm.Algorithm)

	out.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(in.CertificationRequestInfo.SubjectPKInfo.Algorithm.Algorithm)
	var err error
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.CertificationRequestInfo.SubjectPKInfo)
	if err != nil {
		return nil, err
	}

	out.Version = in.CertificationRequestInfo.Version

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(in.CertificationRequestInfo.Subject.FullBytes, &subject); err != nil {
		return nil, err
	}
	out.Subject.FillFromRDNSequence(&subject)

	return out, nil
}

// CreateCertificateSigningRequest creates a new certificate signing request
// based on a template. The following members of template are used: Subject.
//
// The certificate signing request is signed with the parameter priv which is
// the private key of the requester. The public part of the priv key is
// included in the certification request information
//
// The returned slice is the certificate signing request in DER encoding.
//
// The only supported key type are RSA and ECDSA (*rsa.PrivateKey or
// *ecdsa.PrivateKey for priv)
func CreateCertificateSigningRequest(rand io.Reader, template *CertificateSigningRequest, priv interface{}) (csr []byte, err error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var signatureAlgorithm pkix.AlgorithmIdentifier
	var hashFunc crypto.Hash

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		signatureAlgorithm.Algorithm = oidSignatureSHA1WithRSA
		hashFunc = crypto.SHA1

		publicKeyBytes, err = asn1.Marshal(rsaPublicKey{
			N: priv.PublicKey.N,
			E: priv.PublicKey.E,
		})
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
	case *ecdsa.PrivateKey:
		switch priv.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA512
		default:
			return nil, errors.New("x509: unknown elliptic curve")
		}

		oid, ok := oidFromNamedCurve(priv.PublicKey.Curve)
		if !ok {
			return nil, errors.New("x509: unknown elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
		publicKeyBytes = elliptic.Marshal(priv.PublicKey.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	default:
		return nil, errors.New("x509: only RSA private keys supported")
	}

	if err != nil {
		return
	}

	var asn1Subject []byte
	if len(template.RawSubject) > 0 {
		asn1Subject = template.RawSubject
	} else {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
	}

	if err != nil {
		return
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := certificationRequestInfo{
		Version:       0,
		Subject:       asn1.RawValue{FullBytes: asn1Subject},
		SubjectPKInfo: publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
	}

	csrInfoContents, err := asn1.Marshal(c)
	if err != nil {
		return
	}

	c.Raw = csrInfoContents

	if !hashFunc.Available() {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	h := hashFunc.New()
	h.Write(csrInfoContents)
	digest := h.Sum(nil)

	var signature []byte

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand, priv, hashFunc, digest)
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand, priv, digest); err == nil {
			signature, err = asn1.Marshal(ecdsaSignature{r, s})
		}
	default:
		panic("internal error")
	}

	if err != nil {
		return
	}

	csr, err = asn1.Marshal(certificateSigningRequest{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})

	return
}
