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

// This has been modified by lsikidi.
package attest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// CertificationParameters encapsulates the inputs for certifying an application key.
// Only TPM 2.0 is supported at this point.
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
}

// VerifyOpts specifies options for the key certification's verification.
type VerifyOpts struct {
	// Public is the public key used to verify key ceritification.
	Public crypto.PublicKey
	// Hash is the hash function used for signature verification. It can be
	// extracted from the properties of the certifying key.
	Hash crypto.Hash
}

// ActivateOpts specifies options for the key certification's challenge generation.
type ActivateOpts struct {
	// EK, the endorsement key, describes an asymmetric key whose
	// private key is permanently bound to the TPM.
	//
	// Activation will verify that the provided EK is held on the same
	// TPM as the key we're certifying. However, it is the caller's responsibility to
	// ensure the EK they provide corresponds to the the device which
	// they are trying to associate the certified key with.
	//
	// Note; LabeledEncapsulationKey interface is a representation of a public key
	EK tpm2.LabeledEncapsulationKey
	// VerifierKeyNameDigest is the name digest of the public key we're using to
	// verify the certification of the tpm-generated key being activated.
	// The verifier key (usually the AK) that owns this digest should be the same
	// key used in VerifyOpts.Public.
	// Use tpm2.ObjectName() to produce the digest for a provided key.
	VerifierKeyNameDigest *tpm2.TPM2BName
}

// CertifyOpts specifies options for the key's certification.
type CertifyOpts struct {
	// QualifyingData is the user provided qualifying data.
	QualifyingData []byte
}

// NewActivateOpts creates options for use in generating an activation challenge for a certified key.
// The computed hash is the name digest of the public key used to verify the certification of our key.
func NewActivateOpts(verifierPubKey *tpm2.TPMTPublic, ek *tpm2.TPMTPublic) (*ActivateOpts, error) {
	pubName, err := tpm2.ObjectName(verifierPubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve a tpm2.Public Name struct from the given public key struct: %w", err)
	}

	key, err := tpm2.ImportEncapsulationKey(ek)
	if err != nil {
		return nil, fmt.Errorf("unable to import encapsulation key: %w", err)
	}

	return &ActivateOpts{
		EK:                    key,
		VerifierKeyNameDigest: pubName,
	}, nil
}

// Verify validates the TPM2-produced certification parameters checking whether:
//
//   - the key length is crypto secure
//   - the attestation parameters matched the attested key
//   - the key was TPM-generated and resides within TPM
//   - the key cannot be duplicated outside the TPM
//   - the key can sign/decrypt outside-TPM objects
//   - the signature is successfuly verified against the passed public key
func (p *CertificationParameters) Verify(opts VerifyOpts) error {
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

	// Make sure the key has sane parameters (e.g., attestation can be faked if an AK
	// can be used for arbitrary signatures).
	if err := att.Magic.Check(); err != nil {
		return errors.New("creation attestation was not produced by a TPM")
	}
	if !pub.ObjectAttributes.FixedTPM {
		return errors.New("provided key is exportable")
	}
	if pub.ObjectAttributes.Restricted {
		return errors.New("provided key is restricted")
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

	return tpmcrypto.VerifySignature(opts.Public, p.CreateSignature, opts.Hash, tpm2.Marshal(att))
}

// Generate returns a credential activation challenge, which can be provided
// to the TPM to verify the AK parameters given are authentic & the AK
// is present on the same TPM as the EK.
//
// The caller is expected to verify the secret returned from the TPM as
// as result of calling ActivateCredential() matches the secret returned here.
// The caller should use subtle.ConstantTimeCompare to avoid potential
// timing attack vectors.
func (p *CertificationParameters) Generate(rnd io.Reader, verifyOpts VerifyOpts, activateOpts ActivateOpts) (secret []byte, ec *EncryptedCredential, err error) {
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

// TODO(lsikidi): include authN parameters?
// certify uses AK's handle and the passed signature scheme to certify the key
// with the `hnd` handle.
func certify(tpm transport.TPM, keyHnd any, akHnd handle, qualifyingData []byte, scheme tpm2.TPMTSigScheme) (*CertificationParameters, error) {
	kHnd, err := tpmutil.ToHandle(tpm, keyHnd)
	if err != nil {
		return nil, fmt.Errorf("could not get handle from %T: %w", kHnd, err)
	}

	rspReadPublic, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(kHnd.HandleValue()),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2.ReadPublic() failed: %w", err)
	}

	pub, err := rspReadPublic.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not encode public key: %w", err)
	}

	rspCertify, err := tpm2.Certify{
		// The handle of the key to certify.
		ObjectHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(kHnd.HandleValue()),
			Name:   *kHnd.KnownName(),
			Auth:   tpmutil.NoAuth,
		},
		// The handle of the AK that will sign the certification.
		SignHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(akHnd.HandleValue()),
			Name:   *akHnd.KnownName(),
			Auth:   tpmutil.NoAuth,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: qualifyingData,
		},
		InScheme: scheme,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Certify() failed: %w", err)
	}

	att, err := rspCertify.CertifyInfo.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not decode certify info: %w", err)
	}
	return &CertificationParameters{
		Public:            pub,
		CreateAttestation: att,
		CreateSignature:   rspCertify.Signature,
	}, nil
}
