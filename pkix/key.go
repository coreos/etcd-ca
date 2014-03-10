package pkix

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
)

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	// key bits for RSA generation
	rsaBits = 1024
)

type Key struct {
	pub          crypto.PublicKey
	priv         crypto.PrivateKey
	privPEMBlock *pem.Block
	// TODO(yichengq): add pemEncryptedBlock *pem.Block
}

func NewKey(pub crypto.PublicKey, priv crypto.PrivateKey) *Key {
	return &Key{pub: pub, priv: priv}
}

// NewKeyFromRSAPrivateKeyPEM inits Key from PEM-format rsa private key bytes
func NewKeyFromRSAPrivateKeyPEM(data []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}

	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &Key{&priv.PublicKey, priv, pemBlock}, nil
}

// CreateRSAKey creates a new Key using RSA algorithm
func CreateRSAKey() (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

func (k *Key) buildPrivatePEMBlock() error {
	if k.privPEMBlock != nil {
		return nil
	}

	switch priv := k.priv.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		k.privPEMBlock = &pem.Block{
			Type:  rsaPrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	default:
		return errors.New("only RSA private key is supported")
	}
	return nil
}

// ExportPrivate exports PEM-format private key
func (k *Key) ExportPrivate() ([]byte, error) {
	if err := k.buildPrivatePEMBlock(); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, k.privPEMBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// GenerateSubjectKeyId generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func (k *Key) GenerateSubjectKeyId() ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
