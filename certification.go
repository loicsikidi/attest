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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// CertificationParameters encapsulates the inputs for certifying a key.
// The key can be an application key or a storage key (i.e, SKR).
type CertificationParameters struct {
	// Public represents the properties of the application key.
	// The data is represented as a TPMT_PUBLIC structure.
	Public *tpm2.TPMTPublic
	// CreateAttestation represents an assertion as to the details of the key.
	// It is encoded as a TPMS_ATTEST structure.
	CreateAttestation *tpm2.TPMSAttest
	// CreateSignature represents a signature of the CreateAttestation structure.
	// It is encoded as a TPMT_SIGNATURE structure.
	CreateSignature tpm2.TPMTSignature
	// Certificate represents the X.509 certificate associated with the attestation
	// key (AK).
	// This certificate attests to the trustworthiness of the AK.
	Certificate *x509.Certificate
}

// NewActivateConfig creates options for use in generating an activation challenge for a certified key.
// The computed hash is the name digest of the public key used to verify the certification of our key.
func NewActivateConfig(verifierPubKey *tpm2.TPMTPublic, ek *tpm2.TPMTPublic) (*ActivateConfig, error) {
	pubName, err := tpm2.ObjectName(verifierPubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve a tpm2.Public Name struct from the given public key struct: %w", err)
	}

	key, err := tpm2.ImportEncapsulationKey(ek)
	if err != nil {
		return nil, fmt.Errorf("unable to import encapsulation key: %w", err)
	}

	return &ActivateConfig{
		EK:                    key,
		VerifierKeyNameDigest: pubName,
	}, nil
}

// Generate returns a credential activation challenge, which can be provided
// to the TPM to verify the AK parameters given are authentic & the AK
// is present on the same TPM as the EK.
//
// The caller is expected to verify the secret returned from the TPM as
// as result of calling ActivateCredential() matches the secret returned here.
// The caller should use subtle.ConstantTimeCompare to avoid potential
// timing attack vectors.
func (p *CertificationParameters) Generate(rnd io.Reader, verifyOpts VerifyConfig, activateOpts ActivateConfig) (secret []byte, ec *EncryptedCredential, err error) {
	if err := p.Verify(verifyOpts); err != nil {
		return nil, nil, err
	}

	if activateOpts.EK == nil {
		return nil, nil, errors.New("no EK provided")
	}

	// generate a random secret
	secret = make([]byte, activationSecretLen)
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, secret); err != nil {
		return nil, nil, fmt.Errorf("error generating activation secret: %w", err)
	}

	idObject, encSecret, err := tpm2.CreateCredential(rnd, activateOpts.EK, activateOpts.VerifierKeyNameDigest.Buffer, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm2.CreateCredential() failed: %w", err)
	}

	return secret, &EncryptedCredential{
		Credential: idObject,
		Secret:     encSecret,
	}, nil
}

// A list of validation functions for different key types.
var (
	SRKValidateFunc = func(pub *tpm2.TPMTPublic) error {
		if !pub.ObjectAttributes.Restricted {
			return errors.New("provided key is not restricted")
		}
		if pub.ObjectAttributes.SignEncrypt {
			return errors.New("provided key is a signing key")
		}
		if !pub.ObjectAttributes.Decrypt {
			return errors.New("provided key is not a decryption key")
		}
		if !pub.ObjectAttributes.NoDA {
			return errors.New("provided key is subject to dictionary attack protection")
		}
		return nil
	}
	AKValidateFunc = func(pub *tpm2.TPMTPublic) error {
		if !pub.ObjectAttributes.Restricted {
			return errors.New("provided key is not restricted")
		}
		if !pub.ObjectAttributes.SignEncrypt {
			return errors.New("provided key is not a signing key")
		}
		if pub.ObjectAttributes.Decrypt {
			return errors.New("provided key is a decryption key")
		}
		return nil
	}
	SigningAppKeyFunc = func(pub *tpm2.TPMTPublic) error {
		if pub.ObjectAttributes.Restricted {
			return errors.New("provided key is restricted")
		}
		if !pub.ObjectAttributes.SignEncrypt {
			return errors.New("provided key is not a signing key")
		}
		if pub.ObjectAttributes.Decrypt {
			return errors.New("provided key is a decryption key")
		}
		return nil
	}
)

// Verify validates the TPM2-produced certification parameters checking whether:
//
//   - the key length is crypto secure
//   - the attestation parameters matched the attested key
//   - the key was TPM-generated and resides within TPM
//   - the key cannot be duplicated outside the TPM
//   - the signature is successfuly verified against the passed public key
func (p *CertificationParameters) Verify(cfg VerifyConfig) error {
	if err := cfg.CheckAndSetDefaults(*p); err != nil {
		return err
	}

	var (
		pub = p.Public
		att = p.CreateAttestation
	)
	if att.Type != tpm2.TPMSTAttestCertify {
		return fmt.Errorf("attestation does not apply to certification data, got tag %#x", att.Type)
	}

	if err := tpmcrypto.ValidatePublicKey(*pub); err != nil {
		return err
	}

	if !bytes.Equal(cfg.QualifyingData, att.ExtraData.Buffer) {
		return NonceMismatchError{Expected: cfg.QualifyingData, Actual: att.ExtraData.Buffer}
	}

	// Make sure the key has sane parameters (e.g., attestation can be faked if an AK
	// can be used for arbitrary signatures).
	if err := att.Magic.Check(); err != nil {
		return errors.New("creation attestation was not produced by a TPM")
	}
	if !pub.ObjectAttributes.FixedTPM {
		return errors.New("provided key is exportable")
	}
	if !pub.ObjectAttributes.FixedParent {
		return errors.New("provided key can be duplicated to a different parent")
	}
	if !pub.ObjectAttributes.SensitiveDataOrigin {
		return errors.New("provided key is not created by TPM")
	}

	// Verify the attested creation name matches what is computed from
	// the public key.
	certifyInfo, err := att.Attested.Certify()
	if err != nil {
		return fmt.Errorf("could not decode certify info: %w", err)
	}
	pubName, err := tpm2.ObjectName(p.Public)
	if err != nil {
		return fmt.Errorf("could not compute public key name: %w", err)
	}

	if !bytes.Equal(certifyInfo.Name.Buffer, pubName.Buffer) {
		return errors.New("certification refers to a different key")
	}

	// Perform custom validation if provided.
	if cfg.ValidateFunc != nil {
		if err := cfg.ValidateFunc(p.Public); err != nil {
			return fmt.Errorf("custom key validation failed: %w", err)
		}
	}

	signHash, err := getSignHash(cfg.Public)
	if err != nil {
		return err
	}

	return tpmcrypto.VerifySignature(cfg.Public, p.CreateSignature, signHash, tpm2.Marshal(att))
}

func getSignHash(pub crypto.PublicKey) (crypto.Hash, error) {
	hashAlg, err := tpmcrypto.GetSigHashFromPublicKey(pub)
	if err != nil {
		return 0, fmt.Errorf("failed to get hash algorithm from public key: %w", err)
	}
	return hashAlg, nil
}

type certifier interface {
	getHandle() tpmutil.Handle
	getScheme() (*tpm2.TPMTSigScheme, error)
	getCertificate() *x509.Certificate
}

// certifyingKey contains details of a TPM key that could certify other keys.
type certifyingKey struct {
	certificate *x509.Certificate
	ak          *wrappedKey
}

func newCertifyingKey(ak *wrappedKey, cert *x509.Certificate) certifier {
	return &certifyingKey{
		ak:          ak,
		certificate: cert,
	}
}

func (ck *certifyingKey) getHandle() tpmutil.Handle {
	return ck.ak.hnd
}

// Public implements [tpmutil.PublicGetter]
func (ck *certifyingKey) Public() *tpm2.TPMTPublic {
	return ck.ak.hnd.Public()
}

// HasPublic implements [tpmutil.PublicGetter]
func (ck *certifyingKey) HasPublic() bool {
	return ck.ak.hnd.HasPublic()
}

func (ck *certifyingKey) getScheme() (*tpm2.TPMTSigScheme, error) {
	keyType, err := ck.ak.keyType()
	if err != nil {
		return nil, fmt.Errorf("failed to get key type from AK: %w", err)
	}
	scheme, err := keyType.Scheme()
	if err != nil {
		return nil, fmt.Errorf("failed to get signature scheme from AK public key: %w", err)
	}
	hash, err := keyType.HashAlg()
	if err != nil {
		return nil, fmt.Errorf("failed to get hash algorithm from AK public key: %w", err)
	}
	sigScheme := tpmcrypto.GetSigScheme(scheme, hash)
	return &sigScheme, nil
}

func (ck *certifyingKey) getCertificate() *x509.Certificate {
	return ck.certificate
}

// TODO(lsikidi): support AK authorization session
func certify(tpm transport.TPM, cfg CertifyConfig) (*CertificationParameters, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	ak := cfg.certifier
	scheme, err := ak.getScheme()
	if err != nil {
		return nil, err
	}

	rspCertify, err := tpm2.Certify{
		// The handle of the key to certify.
		ObjectHandle: tpmutil.ToAuthHandle(cfg.Handle, cfg.Auth),
		// The handle of the AK that will sign the certification.
		SignHandle: tpmutil.ToAuthHandle(ak.getHandle(), tpmutil.NoAuth),
		QualifyingData: tpm2.TPM2BData{
			Buffer: cfg.QualifyingData,
		},
		InScheme: *scheme,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Certify() failed: %w", err)
	}

	att, err := rspCertify.CertifyInfo.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not decode certify info: %w", err)
	}

	return &CertificationParameters{
		Public:            cfg.Handle.Public(),
		CreateAttestation: att,
		CreateSignature:   rspCertify.Signature,
		Certificate:       ak.getCertificate(),
	}, nil
}
