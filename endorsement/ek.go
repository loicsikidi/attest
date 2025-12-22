// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This has been extracted from tpm.go and modified by lsikidi.
package endorsement

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"

	tpmcrypto "github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	manufacturerIntel     = "INTC" // Intel's ASCII manufacturer ID
	IntelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
	manufacturerAMD       = "AMD" // AMD's ASCII manufacturer ID
	AmdEKCertServiceURL   = "https://ftpm.amd.com/pki/aia/"
)

// Predefined handles for EKs as per TCG specification.
var (
	// RSA EK handle
	//
	// Source: TCG TPM v2.0 Provisioning Guidance v1.0, rev1.0, section 7.8
	RSAHandle tpm2.TPMHandle = 0x81010001
	// ECC EK handle
	//
	// Note: unfortunately TCG TPM v2.0 Provisioning Guidance v1.0, rev1.0, section 7.8
	// does not specify a specific handle for ECC key.
	// However, various TPM2 tools (e.g., go-tpm-tools) use the following handle
	// as the de-facto standard. I've also confirmed with my own TPM (Nuvoton) that the
	// ECC EK is indeed pre-provisioned at this handle.
	//
	// Sources:
	//   - https://docs.kernel.org/security/tpm/tpm-security.html
	//   - https://chromium.googlesource.com/chromiumos/platform2/+/main/vtpm/README.md#glinux-profile
	ECCHandle tpm2.TPMHandle = 0x81010002
)

var HandleByType = map[tpm2.TPMAlgID]tpm2.TPMHandle{
	tpm2.TPMAlgRSA: RSAHandle,
	tpm2.TPMAlgECC: ECCHandle,
}

// EK is a burned-in endorcement key bound to a TPM. This optionally contains
// a certificate that can chain to the TPM manufacturer.
type EK struct {
	// TPMT_PUBLIC represents the public key and its parameters.
	Public *tpm2.TPMTPublic

	// Certificate is the EK certificate for TPMs that provide it.
	Certificate *x509.Certificate

	// For Intel TPMs, Intel hosts certificates at a public URL derived from the
	// Public key. Clients or servers can perform an HTTP GET to this URL, and
	// use ParseEKCertificate on the response body.
	CertificateURL string
}

// GetCertificate returns the EK certificate or nil if not available.
func (ek *EK) GetCertificate() *x509.Certificate {
	return ek.Certificate
}

// GetCertificateURL returns the URL where the EK certificate can be retrieved
// in case it's not available locally.
//
// Note; in such situation [EK.Certificate] is nil.
func (ek *EK) GetCertificateURL() string {
	return ek.CertificateURL
}

// PublicKey returns the public key of the EK as a crypto.PublicKey.
func (ek *EK) PublicKey() (crypto.PublicKey, error) {
	return tpmcrypto.PublicKey(ek.Public)
}

// equal compares two public keys for equality.
func equal(a, b crypto.PublicKey) bool {
	switch pubA := a.(type) {
	case *rsa.PublicKey:
		return pubA.Equal(b)
	case *ecdsa.PublicKey:
		return pubA.Equal(b)
	default:
		return false
	}
}

// MustPublicKey returns the public key of the EK as a crypto.PublicKey.
// It panics if the public key cannot be retrieved
func (ek *EK) MustPublicKey() crypto.PublicKey {
	pub, err := ek.PublicKey()
	if err != nil {
		panic(fmt.Sprintf("ek.MustPublicKey() failed: %v", err))
	}
	return pub
}

// Check verifies that the EK struct can be trusted.
// It ensures that the produced public key matches the certificate
//
// Note: if CertificateURL is set and Certificate is nil,
// the Check is valid. In this situation it's the responsibility
// of the Remote Party to check the binding between the EK public key
// and the certificate once downloaded.
func (ek *EK) Check() error {
	if ek.CertificateURL != "" && ek.Certificate == nil {
		return nil
	}
	if ek.Certificate == nil {
		return errors.New("missing EK certificate")
	}
	pub, err := ek.PublicKey()
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}
	if !equal(ek.Certificate.PublicKey, pub) {
		return errors.New("internal public key doesn't match to EK certificate")
	}
	return nil
}

// ReadEKCertFromNVRAM reads the EK certificate from the NVRAM index specified.
// The function returns nil if the certificate is not found.
func ReadEKCertFromNVRAM(tpm transport.TPM, index tpm2.TPMHandle) (*x509.Certificate, error) {
	// By passing nvramCertIndex as our auth handle we're using the NV index
	// itself as the auth hierarchy, which is the same approach
	// tpm2_getekcertificate takes.
	ekCert, err := tpmutil.NVRead(tpm, tpmutil.NVReadConfig{Index: index})
	if err != nil {
		return nil, fmt.Errorf("failed reading EK cert: %w", err)
	}
	return ParseEKCertificate(ekCert)
}

// ParseEKCertificate parses a raw DER encoded EK certificate blob.
func ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	var wasWrapped bool

	// TCG PC Specific Implementation section 7.3.2 specifies
	// a prefix when storing a certificate in NVRAM. We look
	// for and unwrap the certificate if its present.
	if len(ekCert) > 5 && bytes.Equal(ekCert[:3], []byte{0x10, 0x01, 0x00}) {
		certLen := int(binary.BigEndian.Uint16(ekCert[3:5]))
		if len(ekCert) < certLen+5 {
			return nil, fmt.Errorf("parsing nvram header: ekCert size %d smaller than specified cert length %d", len(ekCert), certLen)
		}
		ekCert = ekCert[5 : 5+certLen]
		wasWrapped = true
	}

	// If the cert parses fine without any changes, we are G2G.
	if c, err := x509.ParseCertificate(ekCert); err == nil {
		return c, nil
	}
	// There might be trailing nonsense in the cert, which Go
	// does not parse correctly. As ASN1 data is TLV encoded, we should
	// be able to just get the certificate, and then send that to Go's
	// certificate parser.
	var cert struct {
		Raw asn1.RawContent
	}
	if _, err := asn1.UnmarshalWithParams(ekCert, &cert, "lax"); err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal() failed, wasWrapped=%v: %w", wasWrapped, err)
	}

	c, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return c, nil
}

// EkCertURL returns the URL where the EK certificate can be retrieved.
// The function expects the manufacturer name in its ASCII representation.
//
// Note: only Intel and AMD are supported if another manufacturer is provided
// an empty string is returned.
func EkCertURL(ekPub crypto.PublicKey, manufacturer string) string {
	var certURL string
	switch manufacturer {
	case manufacturerIntel:
		certURL = intelEKURL(ekPub)
	case manufacturerAMD:
		certURL = amdEKURL(ekPub)
	}
	return certURL
}

func intelEKURL(ekPub crypto.PublicKey) string {
	pubHash := sha256.New()
	switch pub := ekPub.(type) {
	case *rsa.PublicKey:
		pubHash.Write(pub.N.Bytes())
		pubHash.Write([]byte{0x1, 0x00, 0x01})
	case *ecdsa.PublicKey:
		pubHash.Write(pub.X.Bytes())
		pubHash.Write(pub.Y.Bytes())
	default:
		return ""
	}
	return IntelEKCertServiceURL + url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
}

// implementation based on tpm2-tools
// https://github.com/tpm2-software/tpm2-tools/blob/c2d1ee7c60dbcc24c4251eb1a99138d2d29fad73/tools/tpm2_getekcertificate.c#L227-L296
func amdEKURL(ekPub crypto.PublicKey) string {
	pubHash := sha256.New()
	var hash []byte
	switch pub := ekPub.(type) {
	case *rsa.PublicKey:
		pubHash.Write([]byte{0x00, 0x00, 0x22, 0x22})
		expBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(expBytes, uint32(pub.E))
		pubHash.Write(expBytes)
		pubHash.Write(pub.N.Bytes())
		hash = pubHash.Sum(nil)[0:16]
	case *ecdsa.PublicKey:
		pubHash.Write([]byte{0x00, 0x00, 0x44, 0x44})
		pubHash.Write(pub.X.Bytes())
		pubHash.Write(pub.Y.Bytes())
		hash = pubHash.Sum(nil)
	default:
		return ""
	}
	return AmdEKCertServiceURL + url.QueryEscape(fmt.Sprintf("%X", hash))
}
