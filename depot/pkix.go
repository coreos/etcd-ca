package depot

import (
	"strings"

	"github.com/coreos/etcd-ca/pkix"
)

const (
	authPrefix  = "ca"
	hostPadding = ".host"

	crtSuffix     = ".crt"
	crtInfoSuffix = ".crt.info"
	csrSuffix     = ".csr"
	pubKeySuffix  = ".pub.key"
	privKeySuffix = ".key"
)

const (
	rootPerm   = 0400
	branchPerm = 0440
	leafPerm   = 0444
)

func AuthCrtTag() *Tag {
	return &Tag{authPrefix + crtSuffix, leafPerm}
}

func AuthPrivKeyTag() *Tag {
	return &Tag{authPrefix + privKeySuffix, rootPerm}
}

func AuthCrtInfoTag() *Tag {
	return &Tag{authPrefix + crtInfoSuffix, rootPerm}
}

func HostCrtTag(name string) *Tag {
	return &Tag{name + hostPadding + crtSuffix, leafPerm}
}

func HostCsrTag(name string) *Tag {
	return &Tag{name + hostPadding + csrSuffix, leafPerm}
}

func HostPrivKeyTag(name string) *Tag {
	return &Tag{name + hostPadding + privKeySuffix, branchPerm}
}

func GetNameFromHostCrtTag(tag *Tag) string {
	name := strings.TrimSuffix(tag.name, hostPadding+crtSuffix)
	if name == tag.name {
		return ""
	}
	return name
}

func PutCertificateAuthorityInfo(d Depot, info *pkix.CertificateAuthorityInfo) error {
	b, err := info.Export()
	if err != nil {
		return err
	}
	return d.Put(AuthCrtInfoTag(), b)
}

func CheckCertificateAuthorityInfo(d Depot) bool {
	return d.Check(AuthCrtInfoTag())
}

func GetCertificateAuthorityInfo(d Depot) (info *pkix.CertificateAuthorityInfo, err error) {
	b, err := d.Get(AuthCrtInfoTag())
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateAuthorityInfoFromJSON(b)
}

func DeleteCertificateAuthorityInfo(d Depot) error {
	return d.Delete(AuthCrtInfoTag())
}

func UpdateCertificateAuthorityInfo(d Depot, info *pkix.CertificateAuthorityInfo) error {
	DeleteCertificateAuthorityInfo(d)
	return PutCertificateAuthorityInfo(d, info)
}

func PutCertificateAuthority(d Depot, crt *pkix.Certificate) error {
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return d.Put(AuthCrtTag(), b)
}

func CheckCertificateAuthority(d Depot) bool {
	return d.Check(AuthCrtTag())
}

func GetCertificateAuthority(d Depot) (crt *pkix.Certificate, err error) {
	b, err := d.Get(AuthCrtTag())
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateFromPEM(b)
}

func DeleteCertificateAuthority(d Depot) error {
	return d.Delete(AuthCrtTag())
}

func PutCertificateHost(d Depot, name string, crt *pkix.Certificate) error {
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return d.Put(HostCrtTag(name), b)
}

func CheckCertificateHost(d Depot, name string) bool {
	return d.Check(HostCrtTag(name))
}

func GetCertificateHost(d Depot, name string) (crt *pkix.Certificate, err error) {
	b, err := d.Get(HostCrtTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateFromPEM(b)
}

func DeleteCertificateHost(d Depot, name string) error {
	return d.Delete(HostCrtTag(name))
}

func PutCertificateSigningRequest(d Depot, name string, csr *pkix.CertificateSigningRequest) error {
	b, err := csr.Export()
	if err != nil {
		return err
	}
	return d.Put(HostCsrTag(name), b)
}

func CheckCertificateSigningRequest(d Depot, name string) bool {
	return d.Check(HostCsrTag(name))
}

func GetCertificateSigningRequest(d Depot, name string) (crt *pkix.CertificateSigningRequest, err error) {
	b, err := d.Get(HostCsrTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateSigningRequestFromPEM(b)
}

func DeleteCertificateSigningRequest(d Depot, name string) error {
	return d.Delete(HostCsrTag(name))
}

func PutPrivateKeyAuthority(d Depot, key *pkix.Key) error {
	b, err := key.ExportPrivate()
	if err != nil {
		return err
	}
	return d.Put(AuthPrivKeyTag(), b)
}

func CheckPrivateKeyAuthority(d Depot) bool {
	return d.Check(AuthPrivKeyTag())
}

func GetPrivateKeyAuthority(d Depot) (key *pkix.Key, err error) {
	b, err := d.Get(AuthPrivKeyTag())
	if err != nil {
		return nil, err
	}
	return pkix.NewKeyFromPrivateKeyPEM(b)
}

func DeletePrivateKeyAuthority(d Depot) error {
	return d.Delete(AuthPrivKeyTag())
}

func PutPrivateKeyHost(d Depot, name string, key *pkix.Key) error {
	b, err := key.ExportPrivate()
	if err != nil {
		return err
	}
	return d.Put(HostPrivKeyTag(name), b)
}

func CheckPrivateKeyHost(d Depot, name string) bool {
	return d.Check(HostPrivKeyTag(name))
}

func GetPrivateKeyHost(d Depot, name string) (key *pkix.Key, err error) {
	b, err := d.Get(HostPrivKeyTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewKeyFromPrivateKeyPEM(b)
}

func DeletePrivateKeyHost(d Depot, name string) error {
	return d.Delete(HostPrivKeyTag(name))
}

func PutEncryptedPrivateKeyAuthority(d Depot, key *pkix.Key, passphrase []byte) error {
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return err
	}
	return d.Put(AuthPrivKeyTag(), b)
}

func CheckEncryptedPrivateKeyAuthority(d Depot) bool {
	return d.Check(AuthPrivKeyTag())
}

func GetEncryptedPrivateKeyAuthority(d Depot, passphrase []byte) (key *pkix.Key, err error) {
	b, err := d.Get(AuthPrivKeyTag())
	if err != nil {
		return nil, err
	}
	return pkix.NewKeyFromEncryptedPrivateKeyPEM(b, passphrase)
}

func DeleteEncryptedPrivateKeyAuthority(d Depot) error {
	return d.Delete(AuthPrivKeyTag())
}

func PutEncryptedPrivateKeyHost(d Depot, name string, key *pkix.Key, passphrase []byte) error {
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return err
	}
	return d.Put(HostPrivKeyTag(name), b)
}

func CheckEncryptedPrivateKeyHost(d Depot, name string) bool {
	return d.Check(HostPrivKeyTag(name))
}

func GetEncryptedPrivateKeyHost(d Depot, name string, passphrase []byte) (key *pkix.Key, err error) {
	b, err := d.Get(HostPrivKeyTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewKeyFromEncryptedPrivateKeyPEM(b, passphrase)
}

func DeleteEncryptedPrivateKeyHost(d Depot, name string) error {
	return d.Delete(HostPrivKeyTag(name))
}
