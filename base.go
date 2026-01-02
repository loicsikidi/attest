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

// This file has been renamed from wrapped_tpm20.go to base.go and modified by lsikidi.
package attest

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/info"
	"github.com/loicsikidi/attest/kty"
	"github.com/loicsikidi/attest/pcr"
	"github.com/loicsikidi/attest/storage"

	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/loicsikidi/attest/internal/utils"
	pkgslices "github.com/loicsikidi/attest/internal/utils/slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type tpmbase struct {
	rwc transport.TPMCloser
	// cacheInfo caches the TPMInfo at startup.
	// Use this cache only for immutable TPM properties (e.g., PCR banks, Manufacturer, etc.).
	cacheInfo *info.TPMInfo
}

// certifyingKey contains details of a TPM key that could certify other keys.
type certifyingKey struct {
	handle  tpmutil.Handle
	keyType kty.KeyType
}

func (t *tpmbase) tpm() transport.TPM {
	return t.rwc
}

func (t *tpmbase) close() error {
	return t.rwc.Close()
}

// Info returns information about the TPM.
func (t *tpmbase) info() (*info.TPMInfo, error) {
	if t.cacheInfo != nil {
		return t.cacheInfo, nil
	}

	info, err := info.Get(t.rwc)
	if err != nil {
		return nil, err
	}
	t.cacheInfo = info // store in cache
	return t.cacheInfo, nil
}

func (t *tpmbase) ekCertificates(optionalCfg ...SearchEKCertConfig) ([]endorsement.EK, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if cfg.Info == nil {
		cfg.Info = t.cacheInfo
	}
	return endorsement.SearchCertificates(t.rwc, cfg)
}

func (t *tpmbase) eks() ([]endorsement.EK, error) {
	certs, err := t.ekCertificates()
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		return certs, nil
	}

	// Attempt to create a raw RSA EK, as no EK certs were found.
	ek, err := endorsement.Get(t.rwc, endorsement.GetConfig{
		Info:     *t.cacheInfo,
		Template: endorsement.TemplateRSA,
	})
	if err != nil {
		return nil, fmt.Errorf("creating raw RSA EK failed: %w", err)
	}
	return []endorsement.EK{ek}, nil
}

func (t *tpmbase) ek(cfg GetEKCertConfig) (endorsement.EK, error) {
	return endorsement.GetCertificate(t.rwc, cfg)
}

func (t *tpmbase) persistedEKs() []EKCertTemplate {
	return endorsement.SearchPersistedTemplates(t.rwc)
}

func (t *tpmbase) newAK(optionalCfg ...AKConfig) (*AK, error) {
	opts := utils.OptionalArg(optionalCfg)
	if err := opts.CheckAndSetDefaults(); err != nil {
		return nil, err
	}
	srkHandle, err := t.getStorageRootKeyHandle(*opts.Parent)
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK handle: %w", err)
	}

	var akTemplate tpm2.TPMTPublic
	// The default is RSA.
	if slices.Contains([]algorithm.Algorithm{algorithm.ECDSA, algorithm.ECC}, opts.Algorithm) {
		akTemplate = akTemplateECC
	} else {
		akTemplate = akTemplateRSA
	}
	sigScheme, err := tpmcrypto.GetSigSchemeFromPublic(akTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature scheme from AK template: %w", err)
	}

	akCreateResult, err := tpmutil.CreateWithResult(t.rwc, tpmutil.CreateConfig{
		ParentHandle: srkHandle,
		InPublic:     akTemplate,
	})
	if err != nil {
		return nil, fmt.Errorf("CreateKey failed: %w", err)
	}

	createData := akCreateResult.CreationInfo()
	if createData == nil {
		return nil, fmt.Errorf("failed to access creation data")
	}

	akHandle, err := tpmutil.Load(t.rwc, tpmutil.LoadConfig{
		ParentHandle: tpmutil.NewHandle(srkHandle),
		InPublic:     akCreateResult.OutPublic,
		InPrivate:    akCreateResult.OutPrivate,
	})
	if err != nil {
		return nil, fmt.Errorf("Load() failed: %w", err)
	}

	// If any errors occur, free the AK's handle.
	defer func() {
		if err != nil {
			akHandle.Close() //nolint:errcheck // ignore error on close
		}
	}()

	rspCC, err := tpm2.CertifyCreation{
		SignHandle:     tpmutil.ToAuthHandle(akHandle, tpmutil.NoAuth),
		ObjectHandle:   akHandle,
		CreationHash:   akCreateResult.CreationHash,
		InScheme:       sigScheme,
		CreationTicket: akCreateResult.CreationTicket,
	}.Execute(t.rwc)
	if err != nil {
		return nil, fmt.Errorf("CertifyCreation failed: %w", err)
	}

	pubKey, err := tpmcrypto.PublicKey(akCreateResult.OutPublic)
	if err != nil {
		return nil, fmt.Errorf("access public key failed: %w", err)
	}

	return &AK{
		ak: newWrappedAK(
			akHandle,
			akCreateResult.OutPrivate,
			akCreateResult.OutPublic,
			*createData,
			// We can only certify the creation immediately afterwards, so we cache the result.
			rspCC.CertifyInfo,
			rspCC.Signature,
		),
		pub: pubKey,
	}, nil
}

func (t *tpmbase) getStorageRootKeyHandle(parent ParentKeyConfig) (tpmutil.Handle, error) {
	return tpmutil.GetSKRHandle(t.rwc, tpmutil.ParentConfig{
		Handle:    tpmutil.NewHandle(parent.Handle),
		KeyFamily: tpmutil.AlgIDToKeyFamily(tpm2.TPMAlgID(parent.Algorithm)),
	})
}

func (t *tpmbase) getEndorsementKeyHandle(endorsementKey *endorsement.EK) (handle, error) {
	var (
		family     tpmutil.KeyFamily
		kty        tpmutil.KeyType
		isLowRange bool
		ekHandle   tpm2.TPMHandle
	)
	// The default is RSA for backward compatibility.
	if endorsementKey == nil {
		ekHandle = endorsement.RSAHandle
		family = tpmutil.RSA
		isLowRange = true
		kty = tpmutil.RSA2048
	} else {
		family = endorsementKey.KeyFamily()
		isLowRange = endorsementKey.Template.IsLowRange()
		kty = tpmutil.MustPublicToKeyType(*endorsementKey.Public)
		var ok bool
		ekHandle, ok = endorsement.HandleByType[endorsementKey.Public.Type]
		if !ok {
			return nil, fmt.Errorf("unsupported public key type %#x", endorsementKey.Public.Type)
		}
	}

	readPublicRsp, err := tpm2.ReadPublic{
		ObjectHandle: ekHandle,
	}.Execute(t.rwc)
	if err == nil {
		// Found the persistent handle, assume it's the key we want.
		return &tpm2.NamedHandle{Name: readPublicRsp.Name, Handle: ekHandle}, nil
	}

	handle, err := tpmutil.PersistEK(t.rwc, tpmutil.EKParentConfig{
		KeyFamily:  family,
		IsLowRange: isLowRange,
		Handle:     tpmutil.NewHandle(ekHandle),
		KeyType:    kty,
	})
	if err != nil {
		return nil, fmt.Errorf("persist EK failed: %w", err)
	}

	return handle, nil
}

func (t *tpmbase) deserializeAndLoad(opaqueBlob []byte, parent ParentKeyConfig) (tpmutil.HandleCloser, *storage.SerializedKey, error) {
	sKey, err := storage.DeserializeKey(opaqueBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("deserializeKey() failed: %w", err)
	}
	if sKey.Encoding != storage.KeyEncodingEncrypted {
		return nil, nil, fmt.Errorf("unsupported key encoding: %s", sKey.Encoding.String())
	}

	srkHandle, err := t.getStorageRootKeyHandle(parent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SRK handle: %w", err)
	}

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](sKey.Public)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal public key failed: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](sKey.Blob)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal private key failed: %w", err)
	}

	handle, err := tpmutil.Load(t.rwc, tpmutil.LoadConfig{
		ParentHandle: srkHandle,
		InPublic:     *pub,
		InPrivate:    *priv,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Load() failed: %w", err)
	}
	return handle, sKey, nil
}

func (t *tpmbase) loadAK(opaqueBlob []byte) (*AK, error) {
	return t.loadAKWithParent(opaqueBlob, defaultParentConfig)
}

func (t *tpmbase) loadAKWithParent(opaqueBlob []byte, parent ParentKeyConfig) (*AK, error) {
	hnd, sKey, err := t.deserializeAndLoad(opaqueBlob, parent)
	if err != nil {
		return nil, fmt.Errorf("cannot load attestation key: %w", err)
	}

	key, err := serializedKeyToWrappedKey(sKey)
	if err != nil {
		return nil, fmt.Errorf("cannot convert serialized key to wrapped key: %w", err)
	}
	return &AK{ak: newWrappedAK(hnd, key.blob, key.public, key.createData, key.createAttestation, key.createSignature)}, nil
}

func (t *tpmbase) pcrbanks() ([]tpm2.TPMIAlgHash, error) {
	return pkgslices.Convert(t.cacheInfo.PcrBanks, func(p pcr.Bank) tpm2.TPMIAlgHash { return tpm2.TPMIAlgHash(p.Alg) }), nil
}

func (t *tpmbase) newKey(ak *AK, optionalCfg ...KeyConfig) (*Key, error) {
	k, ok := ak.ak.(*wrappedKey)
	if !ok {
		return nil, fmt.Errorf("expected *wrappedKey, got: %T", k)
	}

	akKty, err := k.keyType()
	if err != nil {
		return nil, fmt.Errorf("keyType() failed: %w", err)
	}
	ck := certifyingKey{handle: k.hnd, keyType: akKty}
	return t.newKeyCertifiedByKey(ck, optionalCfg...)
}

func (t *tpmbase) newKeyCertifiedByKey(ck certifyingKey, optionalCfg ...KeyConfig) (*Key, error) {
	opts := utils.OptionalArg(optionalCfg)
	parentHnd, createResult, err := createKey(t, opts)
	if err != nil {
		return nil, fmt.Errorf("cannot create key: %v", err)
	}

	pub := createResult.PublicArea()
	createData := createResult.CreationInfo()
	if createData == nil {
		return nil, fmt.Errorf("failed to access application key's creation data")
	}

	keyHnd, err := tpmutil.Load(t.rwc, tpmutil.LoadConfig{
		ParentHandle: tpmutil.NewHandle(parentHnd),
		InPublic:     createResult.OutPublic,
		InPrivate:    createResult.OutPrivate,
	})
	if err != nil {
		return nil, fmt.Errorf("Load() failed: %v", err)
	}
	// If any errors occur, free the handle.
	defer func() {
		if err != nil {
			keyHnd.Close() //nolint:errcheck // ignore error on close
		}
	}()

	// Certify application key by AK
	certifyOpts := CertifyOpts{QualifyingData: opts.QualifyingData}
	cp, err := certifyByKey(t, keyHnd, ck, certifyOpts)
	if err != nil {
		return nil, fmt.Errorf("certifyByKey() failed: %v", err)
	}

	if !bytes.Equal(tpm2.Marshal(pub), tpm2.Marshal(cp.Public)) {
		return nil, fmt.Errorf("certified incorrect key, expected: %v, certified: %v", tpm2.Marshal(pub), tpm2.Marshal(cp.Public))
	}

	pubKey, err := tpmcrypto.PublicKey(cp.Public)
	if err != nil {
		return nil, fmt.Errorf("access public key: %v", err)
	}
	return &Key{
		key: newWrappedKey(
			keyHnd,
			createResult.OutPrivate,
			createResult.OutPublic,
			*createData,
			tpm2.New2B(*cp.CreateAttestation),
			cp.CreateSignature),
		pub: pubKey,
		tpm: t,
	}, nil
}

func createKey(t *tpmbase, optionalCfg ...KeyConfig) (handle, *tpmutil.CreateResult, error) {
	opts := utils.OptionalArg(optionalCfg)
	if err := opts.CheckAndSetDefaults(); err != nil {
		return nil, nil, err
	}
	srkHnd, err := t.getStorageRootKeyHandle(*opts.Parent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SRK handle: %v", err)
	}

	tmpl, err := templateFromConfig(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("incorrect key options: %v", err)
	}
	createResult, err := tpmutil.CreateWithResult(t.rwc, tpmutil.CreateConfig{
		ParentHandle: srkHnd,
		InPublic:     tmpl,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateKey() failed: %v", err)
	}
	return srkHnd, createResult, nil
}

func (t *tpmbase) loadKey(opaqueBlob []byte) (*Key, error) {
	return t.loadKeyWithParent(opaqueBlob, defaultParentConfig)
}

func (t *tpmbase) loadKeyWithParent(opaqueBlob []byte, parent ParentKeyConfig) (*Key, error) {
	hnd, sKey, err := t.deserializeAndLoad(opaqueBlob, parent)
	if err != nil {
		return nil, fmt.Errorf("cannot load signing key: %v", err)
	}

	key, err := serializedKeyToWrappedKey(sKey)
	if err != nil {
		return nil, fmt.Errorf("cannot convert serialized key to wrapped key: %w", err)
	}

	pub, err := tpmcrypto.PublicKey(key.public)
	if err != nil {
		return nil, fmt.Errorf("access public key: %v", err)
	}
	return &Key{key: newWrappedKey(hnd, key.blob, key.public, key.createData, key.createAttestation, key.createSignature), pub: pub, tpm: t}, nil
}
