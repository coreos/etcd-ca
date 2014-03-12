package pkix

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

const (
	rsaPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCm1J+Tvs8MNZiI2GiWqA/JDC2d/uGagUYSqIDgK7S74tbu8uqT
KxpcdRWNAf92K0kU+W/CyWWA9uAIX1tTOsJtdutXbGMiFqKvI4YVKssYFkwgH3XE
dc+UWHLZT7g+KKhuKyu/Yice89PLJmpVuosOEXwOZUwhkj9QI4q0IxKs3wIDAQAB
AoGAHCjLfq64WAE76+1LShK4B2Fs2bxJ7EBhyYhzqGL4MLaLPO33tjuSSYThzFlH
+3Q287leqexAm9IP4pnl2liStI2X0eQqZAfX6gd/QQ4Rr7zI9URcd8UPKykKO8Lm
ghpDW+tuEV2A89/NUlcFKteLDYp1wCxCHNTAbY1R4QXVdYECQQDNlw4I/6RcSodX
veAYIQy9eSeAzgAwchtpzz+/7xWG95OUaadyZsPDQp2dmbJPKSGJ0v1cetieQ3ji
fb/qr7q/AkEAz7yfwW6v/M9vCqcxkik9I2VGiE5Xg11f7wX7eT0rwtfSPUpWPtgp
L1YF3FLi58xCxPUkzDlyQ+NZaYQ4roo14QJAQHC+h3eJzxvVPF1ZpnaFhcY56Zeo
W4cIrKu3cbPA7aMgcP6E68jmR4fT25hXWZSs3IRzwc8HouPHOkbsJuWaBQJAf2Yu
k3JOe7y7XM0smXaxCAQUPYPOJ8IcE3qXvsLFE7lINk5glin7GAypi3VJst6SFDhD
WPviF8BWFWABYwlgAQJAViX52BxO/KzLm+/QuTzVqKoqEZW+dqJx984TJug9Vy7h
IEzY0Lcuq3pwJlQyyaNQxXF4orPp5Rzi5pNabuGJ8Q==
-----END RSA PRIVATE KEY-----
`
	wrongRSAPrivKeyAuthPEM = `-----BEGIN WRONG RSA PRIVATE KEY-----
MIICWwIBAAKBgQCm1J+Tvs8MNZiI2GiWqA/JDC2d/uGagUYSqIDgK7S74tbu8uqT
KxpcdRWNAf92K0kU+W/CyWWA9uAIX1tTOsJtdutXbGMiFqKvI4YVKssYFkwgH3XE
dc+UWHLZT7g+KKhuKyu/Yice89PLJmpVuosOEXwOZUwhkj9QI4q0IxKs3wIDAQAB
AoGAHCjLfq64WAE76+1LShK4B2Fs2bxJ7EBhyYhzqGL4MLaLPO33tjuSSYThzFlH
+3Q287leqexAm9IP4pnl2liStI2X0eQqZAfX6gd/QQ4Rr7zI9URcd8UPKykKO8Lm
ghpDW+tuEV2A89/NUlcFKteLDYp1wCxCHNTAbY1R4QXVdYECQQDNlw4I/6RcSodX
veAYIQy9eSeAzgAwchtpzz+/7xWG95OUaadyZsPDQp2dmbJPKSGJ0v1cetieQ3ji
fb/qr7q/AkEAz7yfwW6v/M9vCqcxkik9I2VGiE5Xg11f7wX7eT0rwtfSPUpWPtgp
L1YF3FLi58xCxPUkzDlyQ+NZaYQ4roo14QJAQHC+h3eJzxvVPF1ZpnaFhcY56Zeo
W4cIrKu3cbPA7aMgcP6E68jmR4fT25hXWZSs3IRzwc8HouPHOkbsJuWaBQJAf2Yu
k3JOe7y7XM0smXaxCAQUPYPOJ8IcE3qXvsLFE7lINk5glin7GAypi3VJst6SFDhD
WPviF8BWFWABYwlgAQJAViX52BxO/KzLm+/QuTzVqKoqEZW+dqJx984TJug9Vy7h
IEzY0Lcuq3pwJlQyyaNQxXF4orPp5Rzi5pNabuGJ8Q==
-----END WRONG RSA PRIVATE KEY-----
`
	badRSAPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCm1J+Tvs8MNZiI2GiWqA/JDC2d/uGagUYSqIDgK7S74tbu8uqT
dc+UWHLZT7g+KKhuKyu/Yice89PLJmpVuosOEXwOZUwhkj9QI4q0IxKs3wIDAQAB
ghpDW+tuEV2A89/NUlcFKteLDYp1wCxCHNTAbY1R4QXVdYECQQDNlw4I/6RcSodX
veAYIQy9eSeAzgAwchtpzz+/7xWG95OUaadyZsPDQp2dmbJPKSGJ0v1cetieQ3ji
fb/qr7q/AkEAz7yfwW6v/M9vCqcxkik9I2VGiE5Xg11f7wX7eT0rwtfSPUpWPtgp
L1YF3FLi58xCxPUkzDlyQ+NZaYQ4roo14QJAQHC+h3eJzxvVPF1ZpnaFhcY56Zeo
W4cIrKu3cbPA7aMgcP6E68jmR4fT25hXWZSs3IRzwc8HouPHOkbsJuWaBQJAf2Yu
k3JOe7y7XM0smXaxCAQUPYPOJ8IcE3qXvsLFE7lINk5glin7GAypi3VJst6SFDhD
IEzY0Lcuq3pwJlQyyaNQxXF4orPp5Rzi5pNabuGJ8Q==
-----END RSA PRIVATE KEY-----
`

	rsaEncryptedPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,2ef29f8702fc501a

VP9jGydG3iPHjGutyZC+4g5wx0wQ847YcdyyXUfwuC3XJoQ1IeAhPlNhgYuaTBU2
5yonpHwEo4f2QrRY+0bVwQylQxQvqQsOp8uvyXoD2jQE9fwfkJrFmiBYGL0zu9NT
mSQETzqyFkF7IlUy0AQbks+dXrPNJ4BhaDE/BQ4L3Hc6N72EoOPjWf+Pp1SsGED5
IOzvnFTEhJR9JTH1E4vuac4MsY9eXvlKNGy5r06U4TSS7hkcetFzIcpXNl2TQk+k
9hh9LSkHUG5ruLP8v+8GpdOtmgJ4BZ0FUhmkGfhVBGZik4iMBDPvy7pZ2fVldtAL
8n09uLQZ0DL8GrNJNudWEGvZCMYVhseaQkIQu9540oHG3IxPzqR4whNx4ABB6oKQ
t1Sl4NRB9T+zUbjjdigYhEiDGbB/b0yfu6HsNouLEGXvXy7yORfJLkIIfjngIMtM
7FUylgsRL1U1swDvJOKmFEHaMbUfKQ0s14zCFk/Wx7mXxgWWRNxI33Y0ttxya18n
fm6Q0/q3ZHqczaDhsY7Kk5RpYX9aIP2LDjLisN9J4MEVawJ+jiwdHqCHozb63fTx
rvRPORfRDOFxx33eTh0D4f21y/AgOxuENOiQaUNoq9VMg9rzI14i9/wwIk2DlkxF
SH2sSBFOBRXWsJQFgme+278hubaQAVf0vrUSAeiB2ZA9ACb0c8mOYygeTZ2Mjnq4
A3J1riefAkQ1RZ97LHvzYxyBFklUr7+NeZztv3N6cuOZ1JEka2AKE6SOo9xMqWt9
2TR5s0BqeOjU45XGuiXOAipLc1pAkoKqtE/7IKRr/IY=
-----END RSA PRIVATE KEY-----
`
	password      = "123456"
	wrongPassword = "654321"

	subjectKeyIdOfRSAPubKeyAuthBASE64 = "wqt53Slv45QgmFh7AiIj+dx1NOw="
)

func TestCreateRSAKey(t *testing.T) {
	key, err := CreateRSAKey()
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	if err = key.Private.(*rsa.PrivateKey).Validate(); err != nil {
		t.Fatal("Failed to validate private key")
	}
}

func TestRSAKey(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	if err = key.Private.(*rsa.PrivateKey).Validate(); err != nil {
		t.Fatal("Failed validating RSA private key:", err)
	}
}

func TestWrongRSAKey(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(".."))
	if key != nil || err == nil {
		t.Fatal("Expect not to parse RSA private key:", err)
	}

	key, err = NewKeyFromPrivateKeyPEM([]byte(wrongRSAPrivKeyAuthPEM))
	if key != nil || err == nil {
		t.Fatal("Expect not to parse RSA private key:", err)
	}
}

func TestBadRSAKey(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(badRSAPrivKeyAuthPEM))
	if key != nil || err == nil {
		t.Fatal("Expect not to parse bad RSA private key:", err)
	}
}

// TestRSAKeyExport tests the ability to convert rsa key into PEM bytes
func TestRSAKeyExport(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	pemBytes, err := key.ExportPrivate()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(rsaPrivKeyAuthPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

// TestRSAKeyExportEncrypted tests the ability to convert rsa key into encrypted PEM bytes
func TestRSAKeyExportEncrypted(t *testing.T) {
	key, err := NewKeyFromEncryptedPrivateKeyPEM([]byte(rsaEncryptedPrivKeyAuthPEM), []byte(password))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	pemBytes, err := key.ExportPrivate()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(rsaPrivKeyAuthPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}

	pemBytes, err = key.ExportEncryptedPrivate([]byte(password))
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}

	if _, err := NewKeyFromEncryptedPrivateKeyPEM(pemBytes, []byte(wrongPassword)); err == nil {
		t.Fatal("Expect not parsing certificate from PEM:", err)
	}
}

func TestRSAKeyGenerateSubjectKeyId(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	id, err := GenerateSubjectKeyId(key.Public)
	if err != nil {
		t.Fatal("Failed generating SubjectKeyId:", err)
	}
	correctId, _ := base64.StdEncoding.DecodeString(subjectKeyIdOfRSAPubKeyAuthBASE64)
	if bytes.Compare(id, correctId) != 0 {
		t.Fatal("Failed generating correct SubjectKeyId")
	}
}
