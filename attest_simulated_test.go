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
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/pcr"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func setupSimulatedTPM(t *testing.T) *TPM {
	t.Helper()

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	attestTPM, err := OpenTPM(OpenConfig{Transport: tpm})
	if err != nil {
		t.Fatal(err)
	}
	return attestTPM
}

func TestSimEK(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 || (eks[0].Public == nil) {
		t.Errorf("EKs() = %v, want at least 1 EK with populated fields", eks)
	}
}

func TestSimGetEK(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	tests := []struct {
		name    string
		cfg     GetEKCertConfig
		wantErr error
	}{
		{
			name:    "RSA cert not found",
			cfg:     GetEKCertConfig{Template: endorsement.TemplateRSA},
			wantErr: ErrEKCertNotFound,
		},
		{
			name:    "ECC cert not found",
			cfg:     GetEKCertConfig{Template: endorsement.TemplateECC},
			wantErr: ErrEKCertNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tpm.EK(tt.cfg)
			if err == nil {
				t.Fatal("EK() expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("EK() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSimPersistedEKs(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	// Initially, no EKs should be persisted
	persistedEKs := tpm.PersistedEKs()
	if len(persistedEKs) != 0 {
		t.Errorf("PersistedEKs() = %d, want 0 initially", len(persistedEKs))
	}

	tests := []struct {
		name     string
		template endorsement.Template
		handle   tpm2.TPMHandle
	}{
		{
			name:     "RSA EK",
			template: endorsement.TemplateRSA,
			handle:   endorsement.RSAHandle,
		},
		{
			name:     "ECC EK",
			template: endorsement.TemplateECC,
			handle:   endorsement.ECCHandle,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create EK using CreatePrimary
			ekHandle, err := tpmutil.CreatePrimary(tpm.tpm.(*tpmbase).rwc, tpmutil.CreatePrimaryConfig{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				Template:      tt.template.Public,
				Auth:          tpmutil.NoAuth,
			})
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer ekHandle.Close()

			// Persist the EK to the specified handle
			_, err = tpm2.EvictControl{
				Auth:             tpm2.TPMRHOwner,
				ObjectHandle:     ekHandle,
				PersistentHandle: tt.handle,
			}.Execute(tpm.tpm.(*tpmbase).rwc)
			if err != nil {
				t.Fatalf("EvictControl failed: %v", err)
			}

			// Verify the EK is now persisted
			persistedEKs := tpm.PersistedEKs()
			found := false
			for _, tmpl := range persistedEKs {
				if tmpl.Index == tt.template.Index && tmpl.Public.Type == tt.template.Public.Type {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("PersistedEKs() did not find persisted %s EK", tt.name)
			}

			// Clean up: evict the persisted handle
			_, err = tpm2.EvictControl{
				Auth: tpm2.TPMRHOwner,
				ObjectHandle: &tpm2.NamedHandle{
					Handle: tt.handle,
					Name:   tpm2.TPM2BName{Buffer: []byte{}},
				},
				PersistentHandle: tt.handle,
			}.Execute(tpm.tpm.(*tpmbase).rwc)
			if err != nil {
				t.Logf("Warning: failed to clean up persisted handle: %v", err)
			}
		})
	}
}

func TestSimInfo(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	if _, err := tpm.Info(); err != nil {
		t.Errorf("tpm.Info() failed: %v", err)
	}
}

func TestSimAKCreateAndLoad(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()
	for _, test := range []struct {
		name string
		opts []AKConfig
	}{
		{
			name: "NoConfig",
			opts: nil,
		},
		{
			name: "EmptyConfig",
			opts: []AKConfig{},
		},
		{
			name: "RSA",
			opts: []AKConfig{{Algorithm: algorithm.RSA}},
		},
		{
			name: "ECDSA",
			opts: []AKConfig{{Algorithm: algorithm.ECDSA}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ak, err := tpm.NewAK(test.opts...)
			if err != nil {
				t.Fatalf("NewAK() failed: %v", err)
			}

			enc, err := ak.Marshal()
			if err != nil {
				ak.Close(tpm)
				t.Fatalf("ak.Marshal() failed: %v", err)
			}
			if err := ak.Close(tpm); err != nil {
				t.Fatalf("ak.Close() failed: %v", err)
			}

			loaded, err := tpm.LoadAK(enc)
			if err != nil {
				t.Fatalf("LoadAK() failed: %v", err)
			}
			defer loaded.Close(tpm)

			k1, k2 := ak.ak.(*wrappedKey), loaded.ak.(*wrappedKey)

			if !reflect.DeepEqual(k1.public, k2.public) {
				t.Error("Public keys do not match")
			}
		})
	}
}

func TestSimActivateCredential(t *testing.T) {
	testActivateCredential(t, false)
}

func TestSimActivateCredentialWithEK(t *testing.T) {
	testActivateCredential(t, true)
}

func testActivateCredential(t *testing.T, useEK bool) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("EKs() failed: %v", err)
	}
	if len(EKs) == 0 {
		t.Fatalf("No suitable EK found")
	}
	ek := EKs[0]

	ak, err := tpm.NewAK()
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	ap, err := NewActivationParameters(ek, ak.AttestationParameters())
	if err != nil {
		t.Fatalf("NewActivationParameters() failed: %v", err)
	}

	secret, challenge, err := ap.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	var decryptedSecret []byte
	if useEK {
		decryptedSecret, err = ak.ActivateCredentialWithEK(tpm, *challenge, ek)
	} else {
		decryptedSecret, err = ak.ActivateCredential(tpm, *challenge)
	}
	if err != nil {
		t.Errorf("ak.ActivateCredential() failed: %v", err)
	}
	if !bytes.Equal(secret, decryptedSecret) {
		t.Error("secret does not match decrypted secret")
		t.Logf("Secret = %v", secret)
		t.Logf("Decrypted secret = %v", decryptedSecret)
	}
}

func TestParseAKPublic(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	ak, err := tpm.NewAK()
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()
	if _, err := ParseAKPublic(*params.Public); err != nil {
		t.Errorf("parsing AK public blob: %v", err)
	}
}

// func TestSimQuoteAndVerifyAll(t *testing.T) {
// 	sim, tpm := setupSimulatedTPM(t)
// 	defer sim.Close()

// 	ak, err := tpm.NewAK(nil)
// 	if err != nil {
// 		t.Fatalf("NewAK() failed: %v", err)
// 	}
// 	defer ak.Close(tpm)

// 	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
// 	quote256, err := ak.Quote(tpm, nonce, HashSHA256)
// 	if err != nil {
// 		t.Fatalf("ak.Quote(SHA256) failed: %v", err)
// 	}
// 	quote1, err := ak.Quote(tpm, nonce, HashSHA1)
// 	if err != nil {
// 		t.Fatalf("ak.Quote(SHA1) failed: %v", err)
// 	}

// 	// Providing both PCR banks to AKPublic.Verify() ensures we can handle
// 	// the case where extra PCRs of a different digest algorithm are provided.
// 	var pcrs []PCR
// 	for _, alg := range []HashAlg{HashSHA256, HashSHA1} {
// 		p, err := tpm.PCRs(alg)
// 		if err != nil {
// 			t.Fatalf("tpm.PCRs(%v) failed: %v", alg, err)
// 		}
// 		pcrs = append(pcrs, p...)
// 	}

// 	pub, err := ParseAKPublic(ak.AttestationParameters().Public)
// 	if err != nil {
// 		t.Fatalf("ParseAKPublic() failed: %v", err)
// 	}

// 	// Ensure VerifyAll fails if a quote is missing and hence not all PCR
// 	// banks are covered.
// 	if err := pub.VerifyAll([]Quote{*quote256}, pcrs, nonce); err == nil {
// 		t.Error("VerifyAll().err returned nil, expected failure")
// 	}

// 	if err := pub.VerifyAll([]Quote{*quote256, *quote1}, pcrs, nonce); err != nil {
// 		t.Errorf("quote verification failed: %v", err)
// 	}
// }

// func TestSimAttestPlatform(t *testing.T) {
// 	sim, tpm := setupSimulatedTPM(t)
// 	defer sim.Close()

// 	ak, err := tpm.NewAK(nil)
// 	if err != nil {
// 		t.Fatalf("NewAK() failed: %v", err)
// 	}
// 	defer ak.Close(tpm)

// 	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
// 	attestation, err := tpm.attestPlatform(ak, nonce, nil)
// 	if err != nil {
// 		t.Fatalf("AttestPlatform() failed: %v", err)
// 	}

// 	pub, err := ParseAKPublic(attestation.Public)
// 	if err != nil {
// 		t.Fatalf("ParseAKPublic() failed: %v", err)
// 	}
// 	if err := pub.VerifyAll(attestation.Quotes, attestation.PCRs, nonce); err != nil {
// 		t.Errorf("quote verification failed: %v", err)
// 	}
// }

// func TestSimPCRs(t *testing.T) {
// 	sim, tpm := setupSimulatedTPM(t)
// 	defer sim.Close()

// 	PCRs, err := tpm.PCRs(HashSHA256)
// 	if err != nil {
// 		t.Fatalf("PCRs() failed: %v", err)
// 	}
// 	if len(PCRs) != 24 {
// 		t.Errorf("len(PCRs) = %d, want %d", len(PCRs), 24)
// 	}

// 	for i, pcr := range PCRs {
// 		if len(pcr.Digest) != pcr.DigestAlg.Size() {
// 			t.Errorf("PCR %d len(digest) = %d, expected match with digest algorithm size (%d)", pcr.Index, len(pcr.Digest), pcr.DigestAlg.Size())
// 		}
// 		if pcr.Index != i {
// 			t.Errorf("PCR index %d does not match map index %d", pcr.Index, i)
// 		}
// 		if pcr.DigestAlg != crypto.SHA256 {
// 			t.Errorf("pcr.DigestAlg = %v, expected crypto.SHA256", pcr.DigestAlg)
// 		}
// 	}
// }

func TestSimPersistenceSRK(t *testing.T) {
	testPersistenceSRK(t, defaultParentConfig)
}

func TestSimPersistenceECCSRK(t *testing.T) {
	parentConfig := ParentKeyConfig{
		Algorithm: algorithm.ECDSA,
		Handle:    0x81000002,
	}
	testPersistenceSRK(t, parentConfig)
}

func testPersistenceSRK(t *testing.T, parentConfig ParentKeyConfig) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	_, err := tpm2.ReadPublic{
		ObjectHandle: parentConfig.Handle,
	}.Execute(tpm.tpm.(*tpmbase).rwc)
	if err == nil {
		t.Fatalf("skrhandle shouldn't exist")
	}

	srkHnd, err := tpm.tpm.(*tpmbase).getStorageRootKeyHandle(parentConfig)
	if err != nil {
		t.Fatalf("getStorageRootKeyHandle() failed: %v", err)
	}
	if tpm2.TPMHandle(srkHnd.HandleValue()) != parentConfig.Handle {
		t.Fatalf("bad SRK-equivalent handle: got 0x%x, wanted 0x%x", srkHnd, parentConfig.Handle)
	}

	_, err = tpm2.ReadPublic{
		ObjectHandle: parentConfig.Handle,
	}.Execute(tpm.tpm.(*tpmbase).rwc)
	if err != nil {
		t.Fatalf("skrhandle should exist")
	}
}

func TestSimPersistenceEK(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 || (eks[0].Public == nil) {
		t.Errorf("EKs() = %v, want at least 1 EK with populated fields", eks)
	}

	_, err = tpm2.ReadPublic{
		ObjectHandle: endorsement.RSAHandle,
	}.Execute(tpm.tpm.(*tpmbase).rwc)
	if err == nil {
		t.Fatalf("ekhandle shouldn't exist")
	}

	ek := eks[0]
	ekHnd, err := tpm.tpm.(*tpmbase).getEndorsementKeyHandle(&ek)
	if err != nil {
		t.Fatalf("getStorageRootKeyHandle() failed: %v", err)
	}
	if tpm2.TPMHandle(ekHnd.HandleValue()) != endorsement.RSAHandle {
		t.Fatalf("bad EK-equivalent handle: got 0x%x, wanted 0x%x", ekHnd, endorsement.RSAHandle)
	}

	_, err = tpm2.ReadPublic{
		ObjectHandle: endorsement.RSAHandle,
	}.Execute(tpm.tpm.(*tpmbase).rwc)
	if err != nil {
		t.Fatalf("ekhandle should exist")
	}
}

func TestSignMsg(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	type args struct {
		cfg  []AKConfig
		opts crypto.SignerOpts
	}
	tests := []struct {
		name string
		args args
	}{
		{"no config", args{nil, crypto.SHA256}},
		{"rsa 2048", args{[]AKConfig{{Algorithm: algorithm.RSA}}, crypto.SHA256}},
		// {"rsa 2048 PSS", args{[]AKConfig{{Algorithm: algorithm.RSA}}, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}}},
		{"ecc P256", args{[]AKConfig{{Algorithm: algorithm.ECC}}, crypto.SHA256}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ak, err := tpm.NewAK(tt.args.cfg...)
			if err != nil {
				t.Fatalf("NewAK() failed: %v", err)
			}
			defer ak.Close(tpm)

			msg := []byte("hello world")
			hash := tt.args.opts.HashFunc()
			h := hash.New()
			if _, err := h.Write(msg); err != nil {
				t.Fatalf("h.Write() failed: %v", err)
			}
			hashed := h.Sum(nil)

			sig, err := ak.SignMsg(tpm, msg, tt.args.opts)
			if err != nil {
				t.Fatalf("SignMsg() failed: %v", err)
			}

			alg := algorithm.RSA // Default to RSA if no config is provided.
			if tt.args.cfg != nil {
				alg = tt.args.cfg[0].Algorithm
			}
			verify(t, hashed, sig, ak.Public(), alg)
		})
	}

}

func verify(t *testing.T, msgDigest, sig []byte, pub crypto.PublicKey, alg algorithm.Algorithm, opts ...crypto.SignerOpts) {
	t.Helper()

	switch alg {
	case algorithm.RSA:
		var pssOpts *rsa.PSSOptions
		if len(opts) > 0 {
			var ok bool
			pssOpts, ok = opts[0].(*rsa.PSSOptions)
			if !ok {
				t.Fatalf("expected rsa.PSSOptions, got %T", opts[0])
			}
		}
		verifyRSA(t, msgDigest, sig, pub, pssOpts)
	case algorithm.ECDSA, algorithm.ECC:
		verifyECDSA(t, msgDigest, sig, pub)
	default:
		t.Fatalf("unsupported signature algorithm %v", alg)
	}
}

func verifyRSA(t *testing.T, msgDigest, sig []byte, pub crypto.PublicKey, opts *rsa.PSSOptions) {
	t.Helper()

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("not an RSA public key")
	}

	if opts != nil {
		if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, msgDigest, sig, opts); err != nil {
			t.Errorf("rsa.VerifyPSS() = %v", err)
		}
		return
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, msgDigest, sig); err != nil {
		t.Errorf("rsa.VerifyPKCS1v15() = %v", err)
	}
}

func verifyECDSA(t *testing.T, msgDigest, sig []byte, pub crypto.PublicKey) {
	t.Helper()

	eccPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("not an ECDSA public key")
	}

	parsed := struct{ R, S *big.Int }{}
	_, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		t.Fatalf("signature parsing failed: %v", err)
	}

	if !ecdsa.Verify(eccPub, msgDigest[:], parsed.R, parsed.S) {
		t.Error("ecdsa.Verify() = false")
	}
}

func TestSimQuote(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()

	debugPCR := uint(16)
	selection := []int{15, int(debugPCR)}

	// Extending PCR 16 (debug)
	digests := [][]byte{
		bytes.Repeat([]byte{0x00}, sha256.Size),
		bytes.Repeat([]byte{0x01}, sha256.Size),
		bytes.Repeat([]byte{0x02}, sha256.Size),
	}
	debugDigest := extendPCR(t, tpm.tpm.(*tpmbase).rwc, debugPCR, digests...)

	expectedPCRs := []pcr.PCR{
		{Index: 15, DigestAlg: crypto.SHA256, Digest: readPCR(t, tpm.tpm.(*tpmbase).rwc, 15)},
		{Index: int(debugPCR), DigestAlg: crypto.SHA256, Digest: debugDigest},
	}
	ak, err := tpm.NewAK()
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	q, err := ak.QuotePCRs(tpm, nonce, tpm2.TPMAlgSHA256, selection)
	if err != nil {
		t.Fatalf("ak.Quote() failed: %v", err)
	}

	pub, err := ParseAKPublic(*ak.AttestationParameters().Public)
	if err != nil {
		t.Fatalf("ParseAKPublic() failed: %v", err)
	}

	if err := pub.Verify(*q, expectedPCRs, nonce); err != nil {
		t.Errorf("quote verification failed: %v", err)
	}
}

func extendPCR(t *testing.T, tpm transport.TPM, pcrIndex uint, digest ...[]byte) []byte {
	t.Helper()

	authHandle := tpm2.AuthHandle{
		Handle: tpm2.TPMHandle(pcrIndex),
		Auth:   tpmutil.NoAuth,
	}

	for _, d := range digest {
		pcrExtend := tpm2.PCRExtend{
			PCRHandle: authHandle,
			Digests: tpm2.TPMLDigestValues{
				Digests: []tpm2.TPMTHA{
					{
						HashAlg: tpm2.TPMAlgSHA256,
						Digest:  d,
					},
				},
			},
		}
		if _, err := pcrExtend.Execute(tpm); err != nil {
			t.Fatalf("failed to extend pcr for test %v", err)
		}
	}

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrIndex),
				},
			},
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("failed to read PCR %d: %v", pcrIndex, err)
	}
	return pcrReadRsp.PCRValues.Digests[0].Buffer
}

func readPCR(t *testing.T, tpm transport.TPM, pcrIndex uint) []byte {
	t.Helper()

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrIndex),
				},
			},
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("failed to read PCR %d: %v", pcrIndex, err)
	}
	return pcrReadRsp.PCRValues.Digests[0].Buffer
}
