package pkix

import (
	"math/big"
)

// CertificateAuthorityInfo includes extra information required for CA
type CertificateAuthorityInfo struct {
	// SerialNumber that has been used so far
	// Recorded to ensure all serial numbers issued by the CA are different
	SerialNumber *big.Int
}

func NewCertificateAuthorityInfo(serialNumber int64) *CertificateAuthorityInfo {
	return &CertificateAuthorityInfo{big.NewInt(serialNumber)}
}

func NewCertificateAuthorityInfoFromJSON(data []byte) (*CertificateAuthorityInfo, error) {
	i := big.NewInt(0)

	if err := i.UnmarshalJSON(data); err != nil {
		return nil, err
	}

	return &CertificateAuthorityInfo{i}, nil
}

func (n *CertificateAuthorityInfo) IncSerialNumber() {
	n.SerialNumber.Add(n.SerialNumber, big.NewInt(1))
}

func (n *CertificateAuthorityInfo) Export() ([]byte, error) {
	return n.SerialNumber.MarshalJSON()
}
