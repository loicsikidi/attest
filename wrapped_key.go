// Copyright 2020 Google Inc.
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

// This has been renamed from wrapped_tpm20.go to wrapped_key.go and modified by lsikidi.
package attest

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/kty"
	"github.com/loicsikidi/attest/quote"
	"github.com/loicsikidi/attest/storage"
	goutils "github.com/loicsikidi/go-utils"

	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// wrappedKey represents a key manipulated through a *tpmbase.
type wrappedKey struct {
	hnd tpmutil.HandleCloser

	// TODO(lsikidi): store all params as TPMT*, this would avoid a decode operation?
	blob              tpm2.TPM2BPrivate
	public            tpm2.TPM2BPublic
	createData        tpm2.TPMSCreationData
	createAttestation tpm2.TPM2BAttest
	createSignature   tpm2.TPMTSignature

	// isPersisted indicates if this key was loaded from persistent TPM storage.
	isPersisted bool
}

func newWrappedAK(hnd tpmutil.HandleCloser, blob tpm2.TPM2BPrivate, public tpm2.TPM2BPublic, createData tpm2.TPMSCreationData, createAttestation tpm2.TPM2BAttest, createSig tpm2.TPMTSignature) ak {
	return &wrappedKey{
		hnd:               hnd,
		blob:              blob,
		public:            public,
		createData:        createData,
		createAttestation: createAttestation,
		createSignature:   createSig,
		isPersisted:       false,
	}
}

func newWrappedKey(hnd tpmutil.HandleCloser, blob tpm2.TPM2BPrivate, public tpm2.TPM2BPublic, createData tpm2.TPMSCreationData, createAttestation tpm2.TPM2BAttest, createSig tpm2.TPMTSignature) key {
	return &wrappedKey{
		hnd:               hnd,
		blob:              blob,
		public:            public,
		createData:        createData,
		createAttestation: createAttestation,
		createSignature:   createSig,
		isPersisted:       false,
	}
}

// newWrappedAKFromPersisted creates a [wrappedKey] from a persistent handle.
func newWrappedAKFromPersisted(hnd tpmutil.HandleCloser, public tpm2.TPM2BPublic) ak {
	return &wrappedKey{
		hnd:         hnd,
		public:      public,
		isPersisted: true,
		// createData, createAttestation, createSignature remain zero-valued
	}
}

// newWrappedKeyFromPersisted creates a [wrappedKey] for an application key from a persistent handle.
func newWrappedKeyFromPersisted(hnd tpmutil.HandleCloser, public tpm2.TPM2BPublic) key {
	return &wrappedKey{
		hnd:         hnd,
		public:      public,
		isPersisted: true,
		// createData, createAttestation, createSignature remain zero-valued
	}
}

func (k *wrappedKey) close() error {
	return k.hnd.Close()
}

func (k *wrappedKey) persist(tpm transport.TPM, cfg PersistConfig) error {
	newHandle, err := tpmutil.Persist(tpm, tpmutil.PersistConfig{
		TransientHandle:  k.hnd,
		PersistentHandle: cfg.Handle,
		Auth:             cfg.Parent.Auth,
		Force:            true,
	})
	if err != nil {
		return fmt.Errorf("failed to persist handle: %w", err)
	}

	k.hnd = tpmutil.NewHandleCloser(tpm, newHandle)
	if err := tpmutil.NVWrite(tpm, tpmutil.NVWriteConfig{
		Index: cfg.CertNVIndex.Handle(),
		Data:  cfg.Certificate.Raw,
	}); err != nil {
		// TODO(lsikidi): if NVWrite fails, we should potentially evict the persisted handle
		// to maintain consistency (transaction-like behavior)
		return fmt.Errorf("failed to write certificate to NVRAM: %w", err)
	}

	if cfg.Chain != nil {
		chainDER := goutils.Reduce(cfg.Chain, []byte{}, func(acc []byte, cert *x509.Certificate) []byte {
			return append(acc, cert.Raw...)
		})
		if err := tpmutil.NVWrite(tpm, tpmutil.NVWriteConfig{
			Index:      cfg.CertChainNVIndexStart.Handle(),
			Data:       chainDER,
			MultiIndex: true,
		}); err != nil {
			return fmt.Errorf("failed to write certificate chain to NVRAM: %w", err)
		}
	}
	return nil
}

func (k *wrappedKey) marshal() ([]byte, error) {
	return (&storage.SerializedKey{
		Encoding: storage.KeyEncodingEncrypted,

		Blob:              tpm2.Marshal(k.blob),
		Public:            tpm2.Marshal(k.public),
		CreateData:        tpm2.Marshal(k.createData),
		CreateAttestation: tpm2.Marshal(k.createAttestation),
		CreateSignature:   tpm2.Marshal(k.createSignature),
	}).Serialize()
}

func (k *wrappedKey) blobs() ([]byte, []byte, error) {
	return tpm2.Marshal(k.public), tpm2.Marshal(k.blob), nil
}

func (k *wrappedKey) attestationParameters() AttestationParameters {
	// TODO(lsikidi): harmonize type between wrappedKey AttestationParameters to avoid cast
	pub, _ := k.tpmPublic()

	if k.isPersisted {
		return AttestationParameters{
			Public: pub,
		}
	}

	createAtt, _ := k.createAttestation.Contents()
	return AttestationParameters{
		Public:            pub,
		CreateData:        k.createData,
		CreateAttestation: *createAtt,
		CreateSignature:   k.createSignature,
	}
}

func (k *wrappedKey) activateCredential(tb tpmBase, in EncryptedCredential, ek *endorsement.EK) ([]byte, error) {
	t, ok := tb.(*tpmbase)
	if !ok {
		return nil, fmt.Errorf("expected *tpmbase, got %T", tb)
	}

	var ekHandle tpmutil.Handle
	if ek != nil && ek.Handle != nil {
		ekHandle = ek.Handle
	} else {
		var err error
		ekHandle, err = t.getEndorsementKeyHandle(ek)
		if err != nil {
			return nil, err
		}
	}

	var (
		policy  tpm2.PolicyCallback
		hashAlg tpm2.TPMIAlgHash
	)
	switch {
	case ek != nil:
		if ek.Template.IsLowRange() {
			policy = tpmutil.EkPolicyACallback
		} else {
			policy = tpmutil.EkPolicyBViaACallback(ek.Public.NameAlg)
		}
		hashAlg = ek.Public.NameAlg
	default: // when ek is nil we fallback to RSA 2048 (low range) key
		policy = tpmutil.EkPolicyACallback
		hashAlg = tpm2.TPMAlgSHA256
	}

	// Get the challenge decrypted.
	activateRsp, err := tpm2.ActivateCredential{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(ekHandle.HandleValue()),
			Name:   *ekHandle.KnownName(),
			Auth:   tpm2.Policy(hashAlg, 16 /* nonceSize */, policy),
		},
		ActivateHandle: k.hnd,
		CredentialBlob: tpm2.TPM2BIDObject{
			Buffer: in.Credential,
		},
		Secret: tpm2.TPM2BEncryptedSecret{
			Buffer: in.Secret,
		},
	}.Execute(t.rwc)
	if err != nil {
		return nil, fmt.Errorf("ActivateCredential failed: %w", err)
	}
	return activateRsp.CertInfo.Buffer, nil
}

func (k *wrappedKey) signMsg(tpm transport.TPM, msg []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error) {
	cfg := tpmutil.HashConfig{
		Hierarchy: tpm2.TPMRHOwner,
		HashAlg:   opts.HashFunc(),
		Data:      msg,
	}
	result, err := tpmutil.Hash(tpm, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to hash message: %v", err)
	}

	return k.signWithValidation(tpm, result.Digest, pub, opts, result.Validation)
}

func (k *wrappedKey) sign(tpm transport.TPM, digest []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error) {
	return k.signWithValidation(tpm, digest, pub, opts, tpmutil.NullTicket)
}

func (k *wrappedKey) signWithValidation(tpm transport.TPM, digest []byte, pub crypto.PublicKey, opts crypto.SignerOpts, validation tpm2.TPMTTKHashCheck) ([]byte, error) {
	cfg := tpmutil.SignConfig{
		KeyHandle:  k.hnd,
		PublicKey:  pub,
		Validation: validation,
		SignerOpts: opts,
		Digest:     digest,
	}
	return tpmutil.Sign(tpm, cfg)
}

func (k *wrappedKey) quote(tpm transport.TPM, nonce []byte, alg tpm2.TPMAlgID, selectedPCRs []int) (*quote.Quote, error) {
	uintPCRs := goutils.Map(selectedPCRs, func(p int) uint { return uint(p) })
	sel := tpmutil.ToTPMLPCRSelection(uintPCRs, tpm2.TPMIAlgHash(alg))
	rspQ, err := tpm2.Quote{
		SignHandle:     k.hnd,
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		PCRSelect:      sel,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to perform a quote: %w", err)
	}

	q, err := rspQ.Quoted.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to access quoted attestation: %w", err)
	}

	return &quote.Quote{
		Quote:     *q,
		Signature: rspQ.Signature,
	}, nil
}

func (k *wrappedKey) certify(thetpm transport.TPM, cfg CertifyConfig) (*CertificationParameters, error) {
	return certify(thetpm, cfg)
}

func (k *wrappedKey) tpmPublic() (*tpm2.TPMTPublic, error) {
	return k.public.Contents()
}

func (k *wrappedKey) keyType() (kty.KeyType, error) {
	pub, err := k.tpmPublic()
	if err != nil {
		return kty.UnspecifiedSignAlgorithm, fmt.Errorf("failed to decode public key: %w", err)
	}

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		return kty.RSA_2048, nil
	case tpm2.TPMAlgECC:
		return kty.ECC_P256, nil
	default:
		return kty.UnspecifiedSignAlgorithm, fmt.Errorf("unsupported key type: %#x", pub.Type)
	}
}

func (k *wrappedKey) certificationParameters(optionalAK ...*AK) CertificationParameters {
	// TODO(lsikidi): harmonize type between wrappedKey CertificationParameters to avoid cast
	pub, _ := k.tpmPublic()
	att, _ := k.createAttestation.Contents()

	var cert *x509.Certificate
	if ak := goutils.OptionalArg(optionalAK); ak != nil {
		cert = ak.GetCertificate()
	}

	return CertificationParameters{
		Public:            pub,
		CreateAttestation: att,
		CreateSignature:   k.createSignature,
		Certificate:       cert,
	}
}

func (k *wrappedKey) decrypt(tpm transport.TPM, ciphertext []byte) ([]byte, error) {
	return nil, errors.ErrUnsupported
}

func (k *wrappedKey) getHandle() tpmutil.HandlePublicGetter {
	return k.hnd
}

func serializedKeyToWrappedKey(sKey *storage.SerializedKey) (*wrappedKey, error) {
	if sKey.Encoding != storage.KeyEncodingEncrypted {
		return nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](sKey.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key failed: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](sKey.Blob)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key failed: %w", err)
	}

	createData, err := tpm2.Unmarshal[tpm2.TPMSCreationData](sKey.CreateData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal creation data failed: %w", err)
	}
	createAttestation, err := tpm2.Unmarshal[tpm2.TPM2BAttest](sKey.CreateAttestation)
	if err != nil {
		return nil, fmt.Errorf("unmarshal attestation failed: %w", err)
	}
	createSignature, err := tpm2.Unmarshal[tpm2.TPMTSignature](sKey.CreateSignature)
	if err != nil {
		return nil, fmt.Errorf("unmarshal signature failed: %w", err)
	}

	return &wrappedKey{
		blob:              *priv,
		public:            *pub,
		createData:        *createData,
		createAttestation: *createAttestation,
		createSignature:   *createSignature,
	}, nil
}
