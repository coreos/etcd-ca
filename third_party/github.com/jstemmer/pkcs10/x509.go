// All contents of the x509.go file are taken from the official Go crypto/x509
// package.
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.
package pkcs10

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case oid.Equal(oidSignatureMD2WithRSA):
		return x509.MD2WithRSA
	case oid.Equal(oidSignatureMD5WithRSA):
		return x509.MD5WithRSA
	case oid.Equal(oidSignatureSHA1WithRSA):
		return x509.SHA1WithRSA
	case oid.Equal(oidSignatureSHA256WithRSA):
		return x509.SHA256WithRSA
	case oid.Equal(oidSignatureSHA384WithRSA):
		return x509.SHA384WithRSA
	case oid.Equal(oidSignatureSHA512WithRSA):
		return x509.SHA512WithRSA
	case oid.Equal(oidSignatureDSAWithSHA1):
		return x509.DSAWithSHA1
	case oid.Equal(oidSignatureDSAWithSHA256):
		return x509.DSAWithSHA256
	case oid.Equal(oidSignatureECDSAWithSHA1):
		return x509.ECDSAWithSHA1
	case oid.Equal(oidSignatureECDSAWithSHA256):
		return x509.ECDSAWithSHA256
	case oid.Equal(oidSignatureECDSAWithSHA384):
		return x509.ECDSAWithSHA384
	case oid.Equal(oidSignatureECDSAWithSHA512):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}

var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return x509.RSA
	case oid.Equal(oidPublicKeyDSA):
		return x509.DSA
	case oid.Equal(oidPublicKeyECDSA):
		return x509.ECDSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

func parsePublicKey(algo x509.PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case x509.RSA:
		p := new(rsaPublicKey)
		_, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case x509.DSA:
		var p *big.Int
		_, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, err
		}
		paramsData := keyData.Algorithm.Parameters.FullBytes
		params := new(dsaAlgorithmParameters)
		_, err = asn1.Unmarshal(paramsData, params)
		if err != nil {
			return nil, err
		}
		if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
			return nil, errors.New("zero or negative DSA parameter")
		}
		pub := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
			Y: p,
		}
		return pub, nil
	case x509.ECDSA:
		paramsData := keyData.Algorithm.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		_, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, err
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("crypto/x509: unsupported elliptic curve")
		}
		x, y := elliptic.Unmarshal(namedCurve, asn1Data)
		if x == nil {
			return nil, errors.New("crypto/x509: failed to unmarshal elliptic curve point")
		}
		pub := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}
		return pub, nil
	default:
		return nil, nil
	}
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}
