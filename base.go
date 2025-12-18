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
	handle  handle
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
	cfg, _ := utils.OptionalArg(optionalCfg)
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

func (t *tpmbase) newAK(opts *AKConfig) (*AK, error) {
	var parent ParentKeyConfig
	if opts != nil && opts.Parent != nil {
		parent = *opts.Parent
	} else {
		parent = defaultParentConfig
	}
	srkHandle, err := t.getStorageRootKeyHandle(parent)
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK handle: %w", err)
	}

	var akTemplate tpm2.TPMTPublic
	// The default is RSA.
	if opts != nil && slices.Contains([]algorithm.Algorithm{algorithm.ECDSA, algorithm.ECC}, opts.Algorithm) {
		akTemplate = akTemplateECC
	} else {
		akTemplate = akTemplateRSA
	}
	sigScheme, err := tpmcrypto.GetSigSchemeFromPublic(akTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature scheme from AK template: %w", err)
	}

	akCreateRsp, err := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic:     tpm2.New2B(akTemplate),
	}.Execute(t.rwc)
	if err != nil {
		return nil, fmt.Errorf("CreateKey failed: %w", err)
	}

	createData, err := akCreateRsp.CreationData.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to access creation data: %w", err)
	}

	load := tpm2.Load{
		ParentHandle: srkHandle,
		InPublic:     akCreateRsp.OutPublic,
		InPrivate:    akCreateRsp.OutPrivate,
	}
	akHnd, err := tpmutil.Load(t.rwc, load)
	if err != nil {
		return nil, fmt.Errorf("Load() failed: %w", err)
	}

	// If any errors occur, free the AK's handle.
	defer func() {
		if err != nil {
			akHnd.Close() //nolint:errcheck // ignore error on close
		}
	}()

	rspCC, err := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(akHnd.HandleValue()),
			Name:   *akHnd.KnownName(),
			Auth:   tpmutil.NoAuth,
		},
		ObjectHandle:   akHnd,
		CreationHash:   akCreateRsp.CreationHash,
		InScheme:       sigScheme,
		CreationTicket: akCreateRsp.CreationTicket,
	}.Execute(t.rwc)
	if err != nil {
		return nil, fmt.Errorf("CertifyCreation failed: %w", err)
	}

	pubKey, err := tpmcrypto.PublicKey(akCreateRsp.OutPublic)
	if err != nil {
		return nil, fmt.Errorf("access public key failed: %w", err)
	}

	return &AK{
		ak: newWrappedAK(
			akHnd,
			akCreateRsp.OutPrivate,
			akCreateRsp.OutPublic,
			*createData,
			// We can only certify the creation immediately afterwards, so we cache the result.
			rspCC.CertifyInfo,
			rspCC.Signature,
		),
		pub: pubKey,
	}, nil
}

func (t *tpmbase) getStorageRootKeyHandle(parent ParentKeyConfig) (handle, error) {
	srkHandle := parent.Handle
	readPublicRsp, err := tpm2.ReadPublic{
		ObjectHandle: srkHandle,
	}.Execute(t.rwc)
	if err == nil {
		// Found the persistent handle, assume it's the key we want.
		return &tpm2.NamedHandle{Name: readPublicRsp.Name, Handle: srkHandle}, nil
	}

	rerr := err // Preserve this failure for later logging, if needed

	var srkTemplate tpm2.TPMTPublic
	switch parent.Algorithm {
	case algorithm.RSA:
		srkTemplate = defaultRSASRKTemplate
	case algorithm.ECDSA, algorithm.ECC:
		srkTemplate = defaultECCSRKTemplate
	default:
		return tpm2.NamedHandle{}, fmt.Errorf("unsupported SRK algorithm: %v", parent.Algorithm)
	}

	srkCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(srkTemplate),
	}
	srkCreateRsp, closer, err := tpmutil.CreatePrimaryWithResponse(t.rwc, srkCreate)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("ReadPublic failed (%v), and then CreatePrimary failed: %v", rerr, err)
	}
	defer closer() //nolint:errcheck // ignore error on close

	handle := &tpm2.NamedHandle{
		Handle: srkCreateRsp.ObjectHandle,
		Name:   srkCreateRsp.Name,
	}

	_, err = tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     handle,
		PersistentHandle: srkHandle,
	}.Execute(t.rwc)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("EvictControl failed: %w", err)
	}

	handle.Handle = srkHandle // Update the handle to the persistent handle.

	return handle, nil
}

// TODO(lsikidi): add this function in tpmutil
func (t *tpmbase) getEndorsementKeyHandle(endorsementKey *endorsement.EK) (handle, error) {
	var (
		ekHandle   tpm2.TPMHandle
		ekTemplate tpm2.TPMTPublic
	)
	// The default is RSA for backward compatibility.
	if endorsementKey == nil {
		ekHandle = endorsement.RSAHandle
		ekTemplate = endorsement.RSAEKTemplate
	} else {
		// TODO(lsikidi): why not use endorsementKey.Public directly?
		ekTpl, err := endorsement.GetTemplate(endorsementKey.Public)
		if err != nil {
			return nil, fmt.Errorf("failed to get EK template: %w", err)
		}
		ekTemplate = ekTpl.Public

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

	rerr := err // Preserve this failure for later logging, if needed

	ekCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(ekTemplate),
	}
	ekCreateRsp, closer, err := tpmutil.CreatePrimaryWithResponse(t.rwc, ekCreate)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("ReadPublic failed (%v), and then CreatePrimary failed: %v", rerr, err)
	}
	defer closer() //nolint:errcheck

	handle := &tpm2.NamedHandle{
		Handle: ekCreateRsp.ObjectHandle,
		Name:   ekCreateRsp.Name,
	}

	_, err = tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     handle,
		PersistentHandle: ekHandle,
	}.Execute(t.rwc)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("EvictControl failed: %w", err)
	}

	handle.Handle = ekHandle // Update the handle to the persistent handle.

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

	load := tpm2.Load{
		ParentHandle: srkHandle,
		InPublic:     *pub,
		InPrivate:    *priv,
	}
	handle, err := tpmutil.Load(t.rwc, load)
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

func (t *tpmbase) newKey(ak *AK, opts *KeyConfig) (*Key, error) {
	k, ok := ak.ak.(*wrappedKey)
	if !ok {
		return nil, fmt.Errorf("expected *wrappedKey, got: %T", k)
	}

	akKty, err := k.keyType()
	if err != nil {
		return nil, fmt.Errorf("keyType() failed: %w", err)
	}
	ck := certifyingKey{handle: k.hnd, keyType: akKty}
	return t.newKeyCertifiedByKey(ck, opts)
}

func (t *tpmbase) newKeyCertifiedByKey(ck certifyingKey, opts *KeyConfig) (*Key, error) {
	parentHnd, createRsp, err := createKey(t, opts)
	if err != nil {
		return nil, fmt.Errorf("cannot create key: %v", err)
	}

	pub, err := createRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to access application key's public key from TPM response: %w", err)
	}
	createData, err := createRsp.CreationData.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to access application key's creation data: %w", err)
	}

	loadCmd := tpm2.Load{
		ParentHandle: parentHnd,
		InPublic:     createRsp.OutPublic,
		InPrivate:    createRsp.OutPrivate,
	}
	keyHnd, err := tpmutil.Load(t.rwc, loadCmd)
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
			createRsp.OutPrivate,
			createRsp.OutPublic,
			*createData,
			tpm2.New2B(*cp.CreateAttestation),
			cp.CreateSignature),
		pub: pubKey,
		tpm: t,
	}, nil
}

func createKey(t *tpmbase, opts *KeyConfig) (handle, *tpm2.CreateResponse, error) {
	var parent ParentKeyConfig
	if opts != nil && opts.Parent != nil {
		parent = *opts.Parent
	} else {
		parent = defaultParentConfig
	}
	srkHnd, err := t.getStorageRootKeyHandle(parent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SRK handle: %v", err)
	}

	tmpl, err := templateFromConfig(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("incorrect key options: %v", err)
	}
	createRsp, err := tpm2.Create{
		ParentHandle: srkHnd,
		InPublic:     tpm2.New2B(tmpl),
	}.Execute(t.rwc)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateKey() failed: %v", err)
	}
	return srkHnd, createRsp, nil
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
