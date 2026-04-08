// Copyright 2021 Google Inc.
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

// This file has been modified by lsikidi.
package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/loicsikidi/attest/internal/utils"
	"github.com/loicsikidi/attest/kty"

	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
)

type key interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	persist(tpmBase, PersistConfig) error
	certificationParameters(...*AK) CertificationParameters
	sign(tpmBase, []byte, crypto.PublicKey, crypto.SignerOpts) ([]byte, error)
	decrypt(tpmBase, []byte) ([]byte, error)
	blobs() ([]byte, []byte, error)
	getHandle() tpmutil.HandlePublicGetter
}

// Key represents a key which can be used for signing and decrypting
// outside-TPM objects.
type Key struct {
	key         key
	pub         crypto.PublicKey
	tpm         tpmBase
	certificate *x509.Certificate
	chain       []*x509.Certificate
}

// signer implements crypto.Signer returned by Key.Private().
type signer struct {
	key key
	pub crypto.PublicKey
	tpm tpmBase
}

// Sign signs digest with the TPM-stored private signing key.
func (s *signer) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.sign(s.tpm, digest, s.pub, opts)
}

// Public returns the public key corresponding to the private signing key.
func (s *signer) Public() crypto.PublicKey {
	return s.pub
}

// KeyConfig encapsulates parameters for minting keys.
type KeyConfig struct {
	// Type of the key to be used
	KeyType kty.KeyType
	// Parent describes the Storage Root Key that will be used as a parent.
	// If nil, the default SRK (i.e. RSA with handle 0x81000001) is assumed.
	// Supported only by TPM 2.0 on Linux.
	Parent *ParentKeyConfig
	// QualifyingData is an optional data that will be included into
	// a TPM-generated signature of the minted key.
	// It may contain any data chosen by the caller.
	QualifyingData []byte
}

func (c *KeyConfig) CheckAndSetDefaults() error {
	if c.KeyType == kty.UnspecifiedSignAlgorithm {
		c.KeyType = kty.ECC_P256
	}
	if c.Parent == nil {
		c.Parent = &defaultParentConfig
	}
	return nil
}

// Public returns the public key corresponding to the private key.
func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

// Private returns an object allowing to use the TPM-backed private key.
// For now it implements only crypto.Signer.
func (k *Key) Private(pub crypto.PublicKey) (crypto.PrivateKey, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		if _, ok := k.pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("incompatible public key types: %T != %T", pub, k.pub)
		}
	case *ecdsa.PublicKey:
		if _, ok := k.pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("incompatible public key types: %T != %T", pub, k.pub)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
	return &signer{k.key, k.pub, k.tpm}, nil
}

// Close unloads the key from the system.
func (k *Key) Close() error {
	return k.key.close(k.tpm)
}

// Marshal encodes the key in a format that can be loaded with tpm.LoadKey().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *Key) Marshal() ([]byte, error) {
	return k.key.marshal()
}

// CertificationParameters returns information about the key required to
// verify key certification.
func (k *Key) CertificationParameters(optionalAK ...*AK) CertificationParameters {
	return k.key.certificationParameters(optionalAK...)
}

// Blobs returns public and private blobs to be used by tpm2.Load().
func (k *Key) Blobs() (pub, priv []byte, err error) {
	return k.key.blobs()
}

// Persist stores the application key and its certificate in the TPM.
//
// This operation relies on the fact that a remote party ensured in a
// ceremony that the application key is trustworthy. Usually, the outcome of this ceremony
// is an x509 certificate that certifies the latter.
// Afterwards, the application key can be loaded with [TPM.LoadKeyFromTPM].
func (k *Key) Persist(tpm *TPM, cfg PersistConfig) error {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid persist config: %w", err)
	}

	if err := validateCertificateMatchesPublicKey(cfg.Certificate, k.pub); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	if err := k.key.persist(tpm.tpm, cfg); err != nil {
		return fmt.Errorf("failed to persist application key: %w", err)
	}

	return nil
}

// GetCertificate returns the x509 certificate that certifies the application key.
func (k *Key) GetCertificate() *x509.Certificate {
	return k.certificate
}

// GetChain returns the certificate chain for the application key, or nil if no chain is available.
func (k *Key) GetChain() []*x509.Certificate {
	return k.chain
}

func (k *Key) GetHandle() tpmutil.HandlePublicGetter {
	return k.key.getHandle()
}

func templateFromConfig(optionalCfg ...KeyConfig) (tpm2.TPMTPublic, error) {
	opts := utils.OptionalArg(optionalCfg)
	if err := opts.CheckAndSetDefaults(); err != nil {
		return tpm2.TPMTPublic{}, err
	}
	var tmpl tpm2.TPMTPublic
	switch opts.KeyType.Kind() {
	case tpm2.TPMAlgRSA:
		tmpl = rsaKeyTemplate
		if opts.KeyType.Size() < 0 || opts.KeyType.Size() > 65535 { // basic sanity check
			return tmpl, fmt.Errorf("incorrect size parameter")
		}
		hash, err := opts.KeyType.HashAlg()
		if err != nil {
			return tmpl, fmt.Errorf("failed to get hash algorithm from key type: %w", err)
		}
		tmpl.NameAlg = hash
		// TODO(lsikidi): support strict scheme (it would require to enrich KeyConfig)
		params, err := tpmcrypto.NewRSASigKeyParameters(opts.KeyType.Size(), tpm2.TPMAlgNull)
		if err != nil {
			return tmpl, fmt.Errorf("failed to create RSA parameters: %w", err)
		}
		tmpl.Parameters = *params

	case tpm2.TPMAlgECC:
		var (
			curveID tpm2.TPMECCCurve
			hashAlg tpm2.TPMAlgID
		)
		switch opts.KeyType.Size() {
		case 256:
			hashAlg = tpm2.TPMAlgSHA256
			curveID = tpm2.TPMECCNistP256
		case 384:
			hashAlg = tpm2.TPMAlgSHA384
			curveID = tpm2.TPMECCNistP384
		case 521:
			hashAlg = tpm2.TPMAlgSHA512
			curveID = tpm2.TPMECCNistP521
		default:
			return tmpl, fmt.Errorf("unsupported key size: %v", opts.KeyType.Size())
		}
		tmpl = ecdsaKeyTemplate
		tmpl.NameAlg = hashAlg
		params, err := tpmcrypto.NewECCSigKeyParameters(curveID)
		if err != nil {
			return tmpl, fmt.Errorf("failed to create ECC parameters: %w", err)
		}
		tmpl.Parameters = *params
		unique, err := tpmcrypto.NewECCKeyUnique(curveID)
		if err != nil {
			return tmpl, fmt.Errorf("failed to create ECC unique: %w", err)
		}
		tmpl.Unique = *unique
	default:
		return tmpl, fmt.Errorf("unsupported algorithm type: %q", opts.KeyType)
	}

	return tmpl, nil
}
