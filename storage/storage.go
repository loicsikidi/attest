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

// This has been extracted from storage.go and modified by lsikidi.
package storage

import (
	"encoding/json"
	"fmt"
)

// keyEncoding indicates how an exported TPM key is represented.
type keyEncoding uint8

func (e keyEncoding) String() string {
	switch e {
	case KeyEncodingInvalid:
		return "invalid"
	case KeyEncodingOSManaged:
		return "os-managed"
	case KeyEncodingEncrypted:
		return "encrypted"
	case KeyEncodingParameterized:
		return "parameterized"
	default:
		return fmt.Sprintf("keyEncoding<%d>", int(e))
	}
}

// Key encodings
const (
	KeyEncodingInvalid keyEncoding = iota
	// Managed by the OS but loadable by name.
	KeyEncodingOSManaged
	// Key fully represented but in encrypted form.
	KeyEncodingEncrypted
	// Parameters stored, but key must be regenerated before use.
	KeyEncodingParameterized
)

// SerializedKey represents a loadable, TPM-backed key.
type SerializedKey struct {
	// Encoding describes the strategy by which the key should be
	// loaded/unloaded.
	Encoding keyEncoding `json:"KeyEncoding"`

	// Public represents the public key, in a TPM-specific format.
	Public []byte

	// The following fields are only valid for TPM 2.0 hardware, holding
	// information returned as the result to a TPM2_CertifyCreation command.
	// These are stored alongside the key for later use, as the certification
	// can only be obtained immediately after the key is generated.
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte

	// Name is only valid for KeyEncodingOSManaged, which is only used
	// on Windows.
	Name string

	// Blob represents the key material for KeyEncodingEncrypted keys. This
	// is only used on Linux.
	Blob []byte `json:"KeyBlob"`
}

// Serialize represents the key in a persistent format which may be
// loaded at a later time using deserializeKey().
func (k *SerializedKey) Serialize() ([]byte, error) {
	return json.Marshal(k)
}

func DeserializeKey(b []byte) (*SerializedKey, error) {
	var k SerializedKey
	var err error
	if err = json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("json.Unmarshal() failed: %w", err)
	}
	return &k, nil
}
