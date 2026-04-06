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

// This file has been modified by lsikidi.
package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/internal/utils"
	"github.com/loicsikidi/attest/pcr"
	"github.com/loicsikidi/attest/quote"

	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var (
	defaultParentConfig = ParentKeyConfig{
		SRKAlgorithm: algorithm.RSA,
		SRKHandle:    SRKHandle,
		Auth:         tpmutil.NoAuth,
	}
	// ErrTPMNotAvailable is returned in response to OpenTPM() when
	// either no TPM is available, or a TPM of the requested version
	// is not available (if TPMVersion was set in the provided config).
	ErrTPMNotAvailable = errors.New("TPM device not available")
	// ErrAttestNotImplemented is returned when the attest library is
	// used on a platform other than Linux.
	ErrAttestNotImplemented = errors.New("attest lib is only implemented for Linux")
)

// OpenTPM initializes access to the TPM based on the
// config provided.
func OpenTPM(optionalCfg ...OpenConfig) (*TPM, error) {
	config := utils.OptionalArg(optionalCfg)

	if config.Transport == nil {
		return autoOpenTPM()
	}
	tpm := &tpmbase{rwc: config.Transport}
	if err := probeTpm(tpm); err != nil {
		return nil, err
	}
	return &TPM{tpm: tpm}, nil
}

// probeTpm performs initial probing of the TPM to ensure we have a valid connection.
func probeTpm(base tpmBase) error {
	// behind the scenes, this also caches the TPM info for later use
	_, err := base.info()
	if err != nil {
		base.close() //nolint:errcheck
		return fmt.Errorf("failed to probe TPM at startup: %w", err)
	}
	return nil
}

type ak interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	persist(tpmBase, PersistConfig) error
	activateCredential(tpm tpmBase, in EncryptedCredential, ek *endorsement.EK) ([]byte, error)
	quote(t tpmBase, nonce []byte, alg tpm2.TPMAlgID, selectedPCRs []int) (*quote.Quote, error)
	attestationParameters() AttestationParameters
	certify(tpm transport.TPM, cfg CertifyConfig) (*CertificationParameters, error)
	signMsg(tb tpmBase, msg []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error)
}

// AK represents a key which can be used for attestation.
type AK struct {
	ak          ak
	pub         crypto.PublicKey
	certificate *x509.Certificate
	chain       []*x509.Certificate
}

// Public returns the public key for the AK. This is only supported for TPM 2.0
// on Linux currently.
func (k *AK) Public() crypto.PublicKey {
	return k.pub
}

// Close unloads the AK from the system.
func (k *AK) Close(t *TPM) error {
	return k.ak.close(t.tpm)
}

// Marshal encodes the AK in a format that can be reloaded with tpm.LoadAK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *AK) Marshal() ([]byte, error) {
	return k.ak.marshal()
}

// ActivateCredential decrypts the secret using the key to prove that the AK
// was generated on the same TPM as the EK. This method can be used with TPMs
// that have the default EK, i.e. RSA EK with handle 0x81010001.
//
// This operation is synonymous with TPM2_ActivateCredential.
func (k *AK) ActivateCredential(tpm *TPM, in EncryptedCredential) (secret []byte, err error) {
	return k.ak.activateCredential(tpm.tpm, in, nil)
}

// ActivateCredentialWithEK decrypts the secret using the key to prove that the AK
// was generated on the same TPM as the EK. This method can be used with TPMs
// that have an ECC EK. The 'ek' argument must be one of EKs returned from
// TPM.EKs() or TPM.EKCertificates().
//
// This operation is synonymous with TPM2_ActivateCredential.
func (k *AK) ActivateCredentialWithEK(tpm *TPM, in EncryptedCredential, ek endorsement.EK) (secret []byte, err error) {
	return k.ak.activateCredential(tpm.tpm, in, &ek)
}

// Quote returns a quote over the platform state, signed by the AK.
//
// This is a low-level API. Consumers seeking to attest the state of the
// platform should use tpm.AttestPlatform() instead.
func (k *AK) Quote(tpm *TPM, nonce []byte, alg tpm2.TPMAlgID) (*quote.Quote, error) {
	pcrs := make([]int, 24)
	for pcr := range pcrs {
		pcrs[pcr] = pcr
	}
	return k.ak.quote(tpm.tpm, nonce, alg, pcrs)
}

// QuotePCRs is like Quote() but allows the caller to select a subset of the PCRs.
func (k *AK) QuotePCRs(tpm *TPM, nonce []byte, alg tpm2.TPMAlgID, pcrs []int) (*quote.Quote, error) {
	return k.ak.quote(tpm.tpm, nonce, alg, pcrs)
}

// AttestationParameters returns information about the AK, typically used to
// generate a credential activation challenge.
func (k *AK) AttestationParameters() AttestationParameters {
	return k.ak.attestationParameters()
}

// GetCertificate returns the x509 certificate that certifies the AK.
func (k *AK) GetCertificate() *x509.Certificate {
	return k.certificate
}

// GetChain returns the certificate chain for the AK, or nil if no chain is available.
//
// The chain is populated when loading an AK from persistent storage with [TPM.LoadAKFromTPM].
func (k *AK) GetChain() []*x509.Certificate {
	return k.chain
}

// Certify uses the attestation key to certify the key with `handle`. It returns
// certification parameters which allow to verify the properties of the attested
// key.
func (k *AK) Certify(tpm *TPM, cfg CertifyConfig) (*CertificationParameters, error) {
	t := tpm.tpm.(*tpmbase)
	cfg.certifier = newCertifyingKey(k.ak.(*wrappedKey), k.certificate)
	return k.ak.certify(t.rwc, cfg)
}

// SignMsg signs the message (not the digest) with the AK. Note that AK is a
// restricted signing key, it cannot sign a digest directly.
func (k *AK) SignMsg(tpm *TPM, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.ak.signMsg(tpm.tpm, msg, k.pub, opts)
}

// Persist stores the AK and its certificate in the TPM.
//
// This operation relies on the fact that a remote party ensured in a
// ceremony that the AK is trustworthy. Usually, the outcome of this ceremony
// is an x509 certificate that certifies the AK.
// Afterwards, the AK can be loaded with [TPM.LoadAKFromTPM].
func (k *AK) Persist(tpm *TPM, cfg PersistConfig) error {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid persist config: %w", err)
	}

	if err := validateCertificateMatchesPublicKey(cfg.Certificate, k.pub); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	if err := k.ak.persist(tpm.tpm, cfg); err != nil {
		return fmt.Errorf("failed to persist AK: %w", err)
	}

	return nil
}

// EncryptedCredential represents encrypted parameters which must be activated
// against a key.
type EncryptedCredential struct {
	Credential []byte
	Secret     []byte
}

// AttestationParameters describes information about a key which is necessary
// for verifying its properties remotely.
type AttestationParameters struct {
	// Public represents the AK's canonical encoding. This blob includes the
	// public key, as well as signing parameters such as the hash algorithm
	// used to generate quotes.
	//
	// Use ParseAKPublic to access the key's data.
	Public *tpm2.TPMTPublic
	// For TPM 2.0 devices, Public is encoded as a TPMT_PUBLIC structure.
	// the TPM Part 2 Structures specification, available at
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf

	// Subsequent fields are only populated for AKs generated on a TPM
	// implementing version 2.0 of the specification. The specific structures
	// referenced for each field are defined in the TPM Revision 2, Part 2 -
	// Structures specification, available here:
	// https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

	// CreateData represents the properties of a TPM 2.0 key. It is encoded
	// as a TPMS_CREATION_DATA structure.
	CreateData tpm2.TPMSCreationData
	// CreateAttestation represents an assertion as to the details of the key.
	// It is encoded as a TPMS_ATTEST structure.
	CreateAttestation tpm2.TPMSAttest
	// CreateSignature represents a signature of the CreateAttestation structure.
	// It is encoded as a TPMT_SIGNATURE structure.
	CreateSignature tpm2.TPMTSignature
}

// TODO(lsikidi): add Scheme: tpm2.TPMAlgID in order to support
// multiple signing algorithms (RSASSA, RSAPSS, ECDSA, ECDAA).
//
// AKPublic holds structured information about an AK's public key.
type AKPublic struct {
	// Public is the public part of the AK. This can either be an *rsa.PublicKey or
	// and *ecdsa.PublicKey.
	Public crypto.PublicKey
	// Hash is the hashing algorithm the AK will use when signing quotes.
	Hash crypto.Hash
}

// ParseAKPublic parses the Public blob from the AttestationParameters,
// returning the public key and signing parameters for the key.
func ParseAKPublic(public tpm2.TPMTPublic) (*AKPublic, error) {
	h, err := tpmcrypto.GetSigHashFromPublic(public)
	if err != nil {
		return nil, fmt.Errorf("get signature hash: %w", err)
	}

	pubKey, err := tpmcrypto.PublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	return &AKPublic{Public: pubKey, Hash: h}, nil
}

// Verify is used to prove authenticity of the PCR measurements. It ensures that
// the quote was signed by the AK, and that its contents matches the PCR and
// nonce combination. An error is returned if a provided PCR index was not part
// of the quote. QuoteVerified() will return true on PCRs which were verified
// by a quote.
//
// Do NOT use this method if you have multiple quotes to verify: Use VerifyAll
// instead.
//
// The nonce is used to prevent replays of Quote and PCRs and is signed by the
// quote. Some TPMs don't support nonces longer than 20 bytes, and if the
// nonce is used to tie additional data to the quote, the additional data should be
// hashed to construct the nonce.
func (a *AKPublic) Verify(quote quote.Quote, pcrs []pcr.PCR, nonce []byte) error {
	return a.validateQuote(quote, pcrs, nonce)
}

// VerifyAll uses multiple quotes to verify the authenticity of all PCR
// measurements. See documentation on Verify() for semantics.
//
// An error is returned if any PCRs provided were not covered by a quote,
// or if no quote/nonce was provided.
func (a *AKPublic) VerifyAll(quotes []quote.Quote, pcrs []pcr.PCR, nonce []byte) error {
	if len(quotes) == 0 {
		return errors.New("no quotes were provided")
	}
	if len(nonce) == 0 {
		return errors.New("no nonce was provided")
	}

	for i, quote := range quotes {
		if err := a.Verify(quote, pcrs, nonce); err != nil {
			return fmt.Errorf("quote %d: %w", i, err)
		}
	}

	var errPCRs []string
	for _, p := range pcrs {
		if !p.QuoteVerified() {
			errPCRs = append(errPCRs, fmt.Sprintf("%d (%s)", p.Index, p.DigestAlg))
		}
	}
	if len(errPCRs) > 0 {
		return fmt.Errorf("some PCRs were not covered by a quote: %s", strings.Join(errPCRs, ", "))
	}
	return nil
}

// validateCertificateMatchesPublicKey verifies that the certificate's public key
// matches the key's public key.
func validateCertificateMatchesPublicKey(cert *x509.Certificate, pub crypto.PublicKey) error {
	switch pubKey := pub.(type) {
	case *rsa.PublicKey:
		if !pubKey.Equal(cert.PublicKey) {
			return errors.New("certificate public key does not match public key")
		}
	case *ecdsa.PublicKey:
		if !pubKey.Equal(cert.PublicKey) {
			return errors.New("certificate public key does not match public key")
		}
	default:
		return fmt.Errorf("%T unsupported public key type", pub)
	}

	return nil
}

func (a *AKPublic) validateQuote(q quote.Quote, pcrs []pcr.PCR, nonce []byte) error {
	rawQuote := q.ToRaw()
	if err := tpmcrypto.VerifySignature(a.Public, q.Signature, a.Hash, rawQuote.Quote); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	att := q.Quote
	if att.Type != tpm2.TPMSTAttestQuote {
		return fmt.Errorf("attestation isn't a quote, tag of type %#x", att.Type)
	}

	if !bytes.Equal(att.ExtraData.Buffer, nonce) {
		return &NonceMismatchError{Expected: att.ExtraData.Buffer, Actual: nonce}
	}

	quoteInfo, err := att.Attested.Quote()
	if err != nil {
		return fmt.Errorf("get quote info: %w", err)
	}

	if len(quoteInfo.PCRSelect.PCRSelections) == 0 {
		return errors.New("quote does not contain PCR selections")
	}

	pcrByIndex := map[int][]byte{}
	pcrSelection := quoteInfo.PCRSelect.PCRSelections[0]
	pcrDigestAlg, err := pcrSelection.Hash.Hash()
	if err != nil {
		return fmt.Errorf("get PCR digest algorithm: %w", err)
	}
	for _, pcr := range pcrs {
		if pcr.DigestAlg == pcrDigestAlg {
			pcrByIndex[pcr.Index] = pcr.Digest
		}
	}

	sigHash := a.Hash.New()
	quotePCRs := make(map[int]struct{}, len(pcrSelection.PCRSelect))
	for _, pcrIndex := range tpmutil.PCRSelectToPCRs(pcrSelection.PCRSelect) {
		digest, ok := pcrByIndex[int(pcrIndex)]
		if !ok {
			return fmt.Errorf("quote was over PCR %d which wasn't provided", pcrIndex)
		}
		quotePCRs[int(pcrIndex)] = struct{}{}
		sigHash.Write(digest)
	}

	for index := range pcrByIndex {
		if _, exists := quotePCRs[index]; !exists {
			return fmt.Errorf("provided PCR %d was not included in quote", index)
		}
	}

	if !bytes.Equal(sigHash.Sum(nil), quoteInfo.PCRDigest.Buffer) {
		return errors.New("quote digest didn't match pcrs provided")
	}

	// If we got this far, all included PCRs with a digest algorithm matching that
	// of the quote are verified. As such, we set their quoteVerified bit.
	for i, pcr := range pcrs {
		if _, exists := quotePCRs[pcr.Index]; exists && pcr.DigestAlg == pcrDigestAlg {
			pcrs[i].SetQuoteVerified(true)
		}
	}
	return nil
}
