// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkix

import (
	"testing"
)

// TODO: we move to standard crypto/x509 now, so the cert file is changed.
// upgrade needed.
func TestCreateCertificateHost(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	csr, err := NewCertificateSigningRequestFromPEM([]byte(csrPEM))
	if err != nil {
		t.Fatal("Failed parsing certificate request from PEM:", err)
	}

	crt, err := CreateCertificateHost(crtAuth, NewCertificateAuthorityInfo(authStartSerialNumber), key, csr, 1)
	if err != nil {
		t.Fatal("Failed creating certificate for host:", err)
	}

	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}

	rawCrtAuth, err := crtAuth.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}
	if err = rawCrt.CheckSignatureFrom(rawCrtAuth); err != nil {
		t.Fatal("Failed to check signature:", err)
	}

	if rawCrt.SerialNumber.Uint64() != authStartSerialNumber {
		t.Fatal("Expect serial number %v instead of %v", authStartSerialNumber, rawCrt.SerialNumber)
	}
}
