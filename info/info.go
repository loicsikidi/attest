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
package info

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/capabilities"
	"github.com/loicsikidi/attest/kty"
	"github.com/loicsikidi/attest/manufacturer"
	"github.com/loicsikidi/attest/pcr"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMInfo contains static information about a TPM, values should not change during the
// application lifetime.
//
// Most of the values are retrieved from the TPM capabilities.
type TPMInfo struct {
	// Vendor of the TPM
	Vendor string `json:"vendor"`
	// Manufacturer of the TPM, only manufacturer includes in TCG
	// TPM Vendor ID Registry are supported.
	//
	// Version of the document: v1.07, Revision 0.02 published on 2024-11-20.
	// See https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
	Manufacturer Manufacturer `json:"manufacturer"`
	// Revision of the TPM, e.g. "1.54"
	// This info is useful to determine if some features are supported by the TPM.
	Revision string `json:"revision"`
	// FirmwareVersion contains the major and minor version of the TPM firmware
	FirmwareVersion FirmwareVersion `json:"firmwareVersion"`
	// Algorithms contains the algorithms supported by the TPM.
	Algorithms []algorithm.Algorithm `json:"algorithms,omitempty"`
	// KeyTypes contains all key types supported by the TPM.
	KeyTypes []kty.KeyType `json:"keyTypes"`
	// NVMaxBufferSize defines in bytes the limit of the TPM's buffer.
	// This information is useful to determine the block size for NV operations (e.g. Read, Write).
	// or Hash operations (e.g., Sequence) and optimize the performance when the TPM allocates
	// more than 1024 bytes (which is the requirement imposed by TCG).
	NVMaxBufferSize int `json:"nvMaxBufferSize,omitempty"`
	// NVIndexMaxSize defines in bytes the maximum size of the TPM's NV index.
	NVIndexMaxSize int `json:"nvIndexMaxSize,omitempty"`
	// PcrBanks contains the PCR banks supported by the TPM.
	//
	// Note: the PCR bank can be empty, if you want to get the available PCR banks,
	// use AvailableBanks() method.
	PcrBanks []pcr.Bank `json:"pcrBanks"`
	// EKCertChains contains the EK certificate chains retrieved from TPM NVRAM.
	//
	// According to TCG TPM v2.0 Provisioning Guidance section 2.2.1.5.2, EK certificate
	// chains may be stored in NV indices 0x01c00100 through 0x01c001ff.
	//
	// This field will be nil if no certificate chains are found or if the retrieval fails.
	// When marshaled to JSON, the certificates are encoded as a PEM bundle.
	EKCertChains CertBundle `json:"ekCertChains,omitempty"`
}

// Get retrieves the TPM information, including vendor, manufacturer,
// firmware version, algorithms supported by the TPM, and EK certificate chains.
func Get(tpm transport.TPM) (*TPMInfo, error) {
	rawInfo, err := capabilities.ReadTpmInfo(tpm)
	if err != nil {
		return nil, err
	}
	keyTypes, err := kty.GetSupportedKeyTypes(tpm)
	if err != nil {
		return nil, err
	}

	// Try to retrieve EK certificate chains
	ekCertChains, err := GetEKCertChains(tpm)
	if err != nil {
		return nil, err
	}

	return &TPMInfo{
		Vendor:       rawInfo.Vendor(),
		Manufacturer: GetManufacturerByID(manufacturer.ID(rawInfo.Manufacturer())),
		Revision:     rawInfo.Revision(),
		FirmwareVersion: FirmwareVersion{
			Major: rawInfo.FirmwareMajor(),
			Minor: rawInfo.FirmwareMinor(),
		},
		Algorithms:      rawInfo.Algorithms(),
		NVMaxBufferSize: rawInfo.NVBufferMaxSize(),
		NVIndexMaxSize:  rawInfo.NVIndexMaxSize(),
		PcrBanks:        rawInfo.PcrBanks(),
		KeyTypes:        keyTypes,
		EKCertChains:    ekCertChains,
	}, nil
}

func (c *TPMInfo) SupportsAlgorithm(alg algorithm.Algorithm) bool {
	return slices.Contains(c.Algorithms, alg)
}

// SupportsAlgorithms return whether all algorithms in the provided
// slice are supported by the TPM
func (c *TPMInfo) SupportsAlgorithms(algs []algorithm.Algorithm) bool {
	for _, alg := range algs {
		if !c.SupportsAlgorithm(alg) {
			return false
		}
	}
	return true
}

// AvailableBanks returns a slice of PCR banks that contain PCRs.
func (c *TPMInfo) AvailableBanks() []pcr.Bank {
	var banks []pcr.Bank
	for _, bank := range c.PcrBanks {
		if bank.IsAvailable() {
			banks = append(banks, bank)
		}
	}
	return banks
}

// CertBundle is an alias for a slice of X.509 certificates that marshals to JSON as a PEM bundle.
type CertBundle []*x509.Certificate

// MarshalJSON marshals the certificate bundle to JSON as a PEM-encoded string.
func (cb CertBundle) MarshalJSON() ([]byte, error) {
	if len(cb) == 0 {
		return nil, nil
	}

	var pemBundle strings.Builder
	for _, cert := range cb {
		if cert == nil {
			continue
		}
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBundle.Write(pem.EncodeToMemory(block))
	}

	return json.Marshal(pemBundle.String())
}

// FirmwareVersion models the TPM firmware version.
type FirmwareVersion struct {
	Major int
	Minor int
}

func (fv FirmwareVersion) String() string {
	return fmt.Sprintf("%d.%d", fv.Major, fv.Minor)
}

// MarshalJSON marshals the TPM firmware version to JSON.
func (fv FirmwareVersion) MarshalJSON() ([]byte, error) {
	if fv.Major == 0 && fv.Minor == 0 {
		return []byte(""), nil
	}
	return json.Marshal(fv.String())
}

// Manufacturer represents a TPM manufacturer
type Manufacturer struct {
	ID    manufacturer.ID `json:"id"`
	Name  string          `json:"name"`
	ASCII string          `json:"ascii"`
	Hex   string          `json:"hex"`
}

// String returns a textual representation of the TPM
// manufacturer. An example looks like this:
//
//	ST Microelectronics (<STM >, 53544D20, 1398033696)
func (m Manufacturer) String() string {
	return fmt.Sprintf("%s (<%s>, %s, %d)", m.Name, m.ASCII, m.Hex, m.ID)
}

// GetManufacturerByID returns a Manufacturer based on its Manufacturer ID
// code.
func GetManufacturerByID(id manufacturer.ID) (m Manufacturer) {
	m.ID = id
	m.ASCII, m.Hex = manufacturer.GetEncodings(id)
	// the FIDO Alliance fake TPM vendor ID doesn't conform to the standard ASCII lookup
	if id == 4294963664 {
		m.ASCII = "FIDO"
	}
	m.Name = manufacturer.GetNameByASCII(m.ASCII)
	return
}

const (
	// EKCertChainIndexStart is the first NV index for EK certificate chains.
	//
	// Source: TCG TPM v2.0 Provisioning Guidance, section 2.2.1.5.2
	EKCertChainIndexStart tpm2.TPMHandle = 0x01c00100
)

// GetEKCertChains retrieves EK certificate chains from TPM NVRAM indices.
//
// According to TCG TPM v2.0 Provisioning Guidance section 2.2.1.5.2, EK certificate
// chains may be stored in NV indices 0x01c00100 through 0x01c001ff. The certificates
// are stored as X.509 DER encoded certificates, potentially concatenated and spanning
// multiple indices.
//
// The function reads all available indices in order and concatenates their contents,
// then parses individual certificates from the buffer. Returns an empty slice if no
// certificates are found or if the indices are not provisioned.
//
// Example usage:
//
//	certs, err := info.GetEKCertChains(tpm)
//	if err != nil {
//	    return fmt.Errorf("failed to get EK cert chains: %w", err)
//	}
//	if len(certs) == 0 {
//	    fmt.Println("No EK certificate chains found in NVRAM")
//	}
func GetEKCertChains(tpm transport.TPM) ([]*x509.Certificate, error) {
	var nilSlice []*x509.Certificate
	data, err := tpmutil.NVRead(tpm, tpmutil.NVReadConfig{
		Index:      EKCertChainIndexStart,
		MultiIndex: true,
	})
	if err != nil {
		if errors.Is(err, tpm2.TPMRCHandle) {
			// Index not defined or not readable
			return nilSlice, nil
		}
		return nil, err
	}

	if len(data) == 0 {
		return nilSlice, nil
	}

	return x509.ParseCertificates(data)
}

// HasEKCertChains indicates if the TPM has EK certificate chains provisioned.

// Example usage:
//
//	tpmInfo, err := info.Get(tpm)
//	if err != nil {
//	    return fmt.Errorf("failed to get TPM info: %w", err)
//	}
//	if tpmInfo.HasEKCertChains() {
//	    fmt.Println("TPM has EK certificate chains")
//	}
func (t *TPMInfo) HasEKCertChains() bool {
	return len(t.EKCertChains) > 0
}
