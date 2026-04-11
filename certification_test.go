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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/internal/testutil"
	"github.com/loicsikidi/attest/kty"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestSimTPMCertificationParameters(t *testing.T) {
	testCertificationParameters(t, setupSimulatedTPM(t))
}

// func TestTPMCertificationParameters(t *testing.T) {
// 	if !*testLocal {
// 		t.SkipNow()
// 	}
// 	tpm, err := OpenTPM(nil)
// 	if err != nil {
// 		t.Fatalf("OpenTPM() failed: %v", err)
// 	}
// 	defer tpm.Close()
// 	testCertificationParameters(t, tpm)
// }

func testCertificationParameters(t *testing.T, tpm *TPM) {
	for _, akKty := range []algorithm.Algorithm{algorithm.RSA, algorithm.ECC} {
		ak := setupAttestationKey(t, tpm, akKty)
		sk, err := tpm.NewKey(ak) // default is RSA-2048
		if err != nil {
			t.Fatal(err)
		}

		akAttestParams := ak.AttestationParameters()
		pub := akAttestParams.Public

		pk, err := tpmcrypto.PublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		correctOpts := VerifyConfig{
			Public: pk,
		}

		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		unsupportedHashKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}

		if err != nil {
			t.Fatal(err)
		}

		skCertParams := sk.CertificationParameters()

		for _, test := range []struct {
			name string
			p    *CertificationParameters
			opts VerifyConfig
			err  error
		}{
			{
				name: "OK",
				p:    &skCertParams,
				opts: correctOpts,
				err:  nil,
			},
			{
				name: "wrong public key",
				p:    &skCertParams,
				opts: VerifyConfig{
					Public: wrongKey.Public(),
				},
				err: cmpopts.AnyError,
			},
			{
				name: "unavailable hash function",
				p:    &skCertParams,
				opts: VerifyConfig{
					Public: unsupportedHashKey.Public(),
				},
				err: cmpopts.AnyError,
			},
			{
				name: "modified Public",
				p: &CertificationParameters{
					Public:            akAttestParams.Public,
					CreateAttestation: skCertParams.CreateAttestation,
					CreateSignature:   skCertParams.CreateSignature,
				},
				opts: correctOpts,
				err:  cmpopts.AnyError,
			},
			{
				name: "modified CreateAttestation",
				p: &CertificationParameters{
					Public:            skCertParams.Public,
					CreateAttestation: &akAttestParams.CreateAttestation,
					CreateSignature:   skCertParams.CreateSignature,
				},
				opts: correctOpts,
				err:  cmpopts.AnyError,
			},
			{
				name: "modified CreateSignature",
				p: &CertificationParameters{
					Public:            skCertParams.Public,
					CreateAttestation: skCertParams.CreateAttestation,
					CreateSignature:   akAttestParams.CreateSignature,
				},
				opts: correctOpts,
				err:  cmpopts.AnyError,
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				err := test.p.Verify(test.opts)
				if test.err == nil && err == nil {
					return
				}
				if got, want := err, test.err; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
					t.Errorf("p.Verify() err = %v, want = %v", got, want)
				}
			})
		}

		// cleanup TPM's resources
		if err := ak.Close(); err != nil {
			t.Fatalf("ak.Close() failed: %v", err)
		}
		if err := sk.Close(); err != nil {
			t.Fatalf("sk.Close() failed: %v", err)
		}
	}
}

func setupAttestationKey(t *testing.T, tpm *TPM, kty algorithm.Algorithm) *AK {
	var (
		ak    *AK
		errAk error
	)
	switch kty {
	case algorithm.RSA:
		ak, errAk = tpm.NewAK()
	case algorithm.ECC, algorithm.ECDSA:
		ak, errAk = tpm.NewAK(AKConfig{Algorithm: algorithm.ECC})
	default:
		t.Fatalf("unsupported key type: %s", kty)
	}
	if errAk != nil {
		t.Fatal(errAk)
	}
	return ak
}

func TestSimTPMKeyCertification(t *testing.T) {
	testKeyCertification(t, setupSimulatedTPM(t))
}

// func TestTPMKeyCertification(t *testing.T) {
// 	if !*testLocal {
// 		t.SkipNow()
// 	}
// 	tpm, err := OpenTPM(nil)
// 	if err != nil {
// 		t.Fatalf("OpenTPM() failed: %v", err)
// 	}
// 	defer tpm.Close()
// 	testKeyCertification(t, tpm)
// }

func testKeyCertification(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK()
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	akAttestParams := ak.AttestationParameters()
	pk, err := tpmcrypto.PublicKeyRSA(akAttestParams.Public)
	if err != nil {
		t.Fatalf("PublicKeyRSA() failed: %v", err)
	}
	verifyOpts := VerifyConfig{
		Public: pk,
	}
	for _, test := range []struct {
		name string
		opts []KeyConfig
		err  error
	}{
		{
			name: "default",
			opts: nil,
			err:  nil,
		},
		{
			name: kty.ECC_P256.String(),
			opts: []KeyConfig{
				{
					KeyType: kty.ECC_P256,
				},
			},
			err: nil,
		},
		{
			name: kty.ECC_P384.String(),
			opts: []KeyConfig{
				{
					KeyType: kty.ECC_P384,
				},
			},
			err: nil,
		},
		{
			name: kty.ECC_P521.String(),
			opts: []KeyConfig{
				{
					KeyType: kty.ECC_P521,
				},
			},
			err: nil,
		},
		{
			name: "nonce mismatch",
			opts: []KeyConfig{
				{
					KeyType:        kty.ECC_P256,
					QualifyingData: []byte("awesome nonce"),
				},
			},
			err: cmpopts.AnyError,
		},
		{
			name: kty.RSA_2048.String(),
			opts: []KeyConfig{
				{
					KeyType: kty.RSA_2048,
				},
			},
			err: nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sk, err := tpm.NewKey(ak, test.opts...)
			if err != nil {
				t.Fatalf("NewKey() failed: %v", err)
			}
			defer func() {
				if err := sk.Close(); err != nil {
					t.Errorf("sk.Close() failed: %v", err)
				}
			}()

			p := sk.CertificationParameters()
			err = p.Verify(verifyOpts)
			if test.err == nil && err == nil {
				return
			}
			if got, want := err, test.err; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
				t.Fatalf("p.Verify() err = %v, want = %v", got, want)
			}
		})
	}
}

func TestKeyActivation(t *testing.T) {
	tpm := setupSimulatedTPM(t)

	ak, err := tpm.NewAK(AKConfig{Algorithm: algorithm.ECC})
	if err != nil {
		t.Fatalf("error creating a new AK using simulated TPM: %v", err)
	}
	akAttestParams := ak.AttestationParameters()
	eks, err := tpm.EKs()
	if err != nil {
		t.Fatalf("unexpected error retrieving EK from tpm: %v", err)
	}

	if len(eks) == 0 {
		t.Fatal("expected at least one EK from the simulated TPM")
	}

	pk, err := tpmcrypto.PublicKeyECDSA(akAttestParams.Public)
	if err != nil {
		t.Fatalf("unable to get ECDSA public key from AK attestation params: %v", err)
	}
	verifyOpts := VerifyConfig{
		Public: pk,
	}

	sk, err := tpm.NewKey(ak)
	if err != nil {
		t.Fatalf("unable to create a new TPM-backed key to certify: %v", err)
	}

	skCertParams := sk.CertificationParameters()
	activateOpts, err := NewActivateConfig(akAttestParams.Public, eks[0].Public)
	if err != nil {
		t.Fatalf("unable to create new ActivateOpts: %v", err)
	}

	wrongActivateOpts, err := NewActivateConfig(skCertParams.Public, eks[0].Public)
	if err != nil {
		t.Fatalf("unable to create wrong ActivateOpts: %v", err)
	}

	for _, test := range []struct {
		name         string
		p            *CertificationParameters
		verifyOpts   VerifyConfig
		activateOpts ActivateConfig
		generateErr  error
		activateErr  error
	}{
		{
			name:         "OK",
			p:            &skCertParams,
			verifyOpts:   verifyOpts,
			activateOpts: *activateOpts,
			generateErr:  nil,
			activateErr:  nil,
		},
		{
			name:         "invalid verify opts",
			p:            &skCertParams,
			verifyOpts:   VerifyConfig{},
			activateOpts: *activateOpts,
			generateErr:  cmpopts.AnyError,
			activateErr:  nil,
		},
		{
			name:         "invalid activate opts",
			p:            &skCertParams,
			verifyOpts:   verifyOpts,
			activateOpts: *wrongActivateOpts,
			generateErr:  nil,
			activateErr:  cmpopts.AnyError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectedSecret, encryptedCredentials, err := test.p.Generate(rand.Reader, test.verifyOpts, test.activateOpts)
			if test.generateErr != nil {
				if got, want := err, test.generateErr; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
					t.Errorf("p.Generate() err = %v, want = %v", got, want)
				}

				return
			} else if err != nil {
				t.Errorf("unexpected p.Generate() error: %v", err)
				return
			}

			actualSecret, err := ak.ActivateCredential(tpm, *encryptedCredentials)
			if test.activateErr != nil {
				if got, want := err, test.activateErr; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
					t.Errorf("p.ActivateCredential() err = %v, want = %v", got, want)
				}

				return
			} else if err != nil {
				t.Errorf("unexpected p.ActivateCredential() error: %v", err)
				return
			}

			if !bytes.Equal(expectedSecret, actualSecret) {
				t.Fatalf("Unexpected bytes decoded, expected %x, but got %x", expectedSecret, actualSecret)
			}
		})
	}
}

func TestKeyActivationWithMultipleEKs(t *testing.T) {
	for _, test := range []struct {
		name   string
		tpmCfg []tpmtest.Template
	}{
		{
			name:   "ECC Low Range",
			tpmCfg: []tpmtest.Template{tpmtest.TemplateECC},
		},
		{
			name:   "RSA Low Range",
			tpmCfg: []tpmtest.Template{tpmtest.TemplateRSA},
		},
		{
			name:   "ECC P-256 High Range",
			tpmCfg: []tpmtest.Template{tpmtest.TemplateECCP256},
		},
		{
			name:   "ECC P-384 High Range",
			tpmCfg: []tpmtest.Template{tpmtest.TemplateECCP384},
		},
		{
			name:   "RSA High Range",
			tpmCfg: []tpmtest.Template{tpmtest.TemplateRSA2048},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tpm := setupSimulatedTPM(t, tpmtest.OpenConfig{EKCerts: test.tpmCfg})

			ak, err := tpm.NewAK(AKConfig{Algorithm: algorithm.ECC})
			if err != nil {
				t.Fatalf("error creating a new AK using simulated TPM: %v", err)
			}

			eks, err := tpm.EKs()
			if err != nil {
				t.Fatalf("unexpected error retrieving EK from tpm: %v", err)
			}
			ek := eks[0]

			params, err := NewActivationParameters(ek, ak.AttestationParameters())
			if err != nil {
				t.Fatalf("unable to create new ActivationParameters: %v", err)
			}
			secret, challenge, err := params.Generate()
			if err != nil {
				t.Fatalf("unable to generate activation parameters: %v", err)
			}

			actualSecret, err := ak.ActivateCredentialWithEK(tpm, *challenge, ek)
			if err != nil {
				t.Fatalf("unable to activate credential with EK: %v", err)
			}

			if !bytes.Equal(secret, actualSecret) {
				t.Fatalf("Unexpected bytes decoded, expected %x, but got %x", secret, actualSecret)
			}
		})
	}
}

func TestSimTPMCertificationWithCertificate(t *testing.T) {
	testCertificationWithCertificate(t, setupSimulatedTPM(t))
}

func testCertificationWithCertificate(t *testing.T, tpm *TPM) {
	ca, err := ekca.New()
	if err != nil {
		t.Fatalf("ekca.New() failed: %v", err)
	}

	// Setup root and intermediate pools for verification
	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Root)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(ca.Intermediate)

	ak, err := tpm.NewAK(AKConfig{Algorithm: algorithm.ECC})
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}

	akCert := testutil.CreateTPMCertificate(t, testutil.CertConfig{
		Pub: ak.Public(),
		CA:  ca,
	})

	persistCfg := PersistConfig{
		Handle:      tpmutil.NewHandle(tpm2.TPMHandle(0x81010100)),
		CertNVIndex: tpmutil.NewHandle(tpm2.TPMHandle(0x01C00100)),
		Parent:      defaultParentConfig,
		Certificate: akCert,
	}

	if err := ak.Persist(persistCfg); err != nil {
		ak.Close()
		t.Fatalf("Persist() failed: %v", err)
	}

	loadCfg := LoadConfig{
		Handle:      persistCfg.Handle,
		CertNVIndex: persistCfg.CertNVIndex,
	}

	loadedAK, err := tpm.LoadAKFromTPM(loadCfg)
	if err != nil {
		t.Fatalf("LoadAKFromTPM() failed: %v", err)
	}

	if loadedAK.GetCertificate() == nil {
		t.Fatal("Loaded AK has no certificate")
	}

	appKey, err := tpm.NewKey(loadedAK, KeyConfig{KeyType: kty.ECC_P256})
	if err != nil {
		t.Fatalf("NewKey() failed: %v", err)
	}
	defer appKey.Close()

	// Note: loaded AK is passed to CertificationParameters to include its certificate
	certParams := appKey.CertificationParameters(loadedAK)

	wrongKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	// Create expired certificate
	expiredNotBefore := time.Now().AddDate(-2, 0, 0) // 2 years ago
	expiredNotAfter := time.Now().AddDate(-1, 0, 0)  // 1 year ago
	expiredCert := testutil.CreateTPMCertificate(t, testutil.CertConfig{
		Pub:       ak.Public(),
		CA:        ca,
		NotBefore: &expiredNotBefore,
		NotAfter:  &expiredNotAfter,
	})

	tests := []struct {
		name       string
		certParams *CertificationParameters
		cfg        VerifyConfig
		wantErr    bool
	}{
		{
			name:       "valid certificate with RootPool and IntermediatePool",
			certParams: &certParams,
			cfg: VerifyConfig{
				RootPool:         rootPool,
				IntermediatePool: intermediatePool,
			},
			wantErr: false,
		},
		{
			name: "expired certificate with RootPool and IntermediatePool",
			certParams: &CertificationParameters{
				Public:            certParams.Public,
				CreateAttestation: certParams.CreateAttestation,
				CreateSignature:   certParams.CreateSignature,
				Certificate:       expiredCert,
			},
			cfg: VerifyConfig{
				RootPool:         rootPool,
				IntermediatePool: intermediatePool,
			},
			wantErr: true,
		},
		{
			name: "expired certificate with SkipCertificateExpiryCheck",
			certParams: &CertificationParameters{
				Public:            certParams.Public,
				CreateAttestation: certParams.CreateAttestation,
				CreateSignature:   certParams.CreateSignature,
				Certificate:       expiredCert,
			},
			cfg: VerifyConfig{
				// Use Public key verification instead of chain verification
				// because the CA certificates have recent validity dates
				Public:                     expiredCert.PublicKey,
				SkipCertificateExpiryCheck: true,
			},
			wantErr: false,
		},
		{
			name:       "valid with Public key only",
			certParams: &certParams,
			cfg: VerifyConfig{
				Public: akCert.PublicKey,
			},
			wantErr: false,
		},
		{
			name:       "wrong public key",
			certParams: &certParams,
			cfg: VerifyConfig{
				Public: wrongKey.Public(),
			},
			wantErr: true,
		},
		{
			name:       "ValidateFunc rejecting key without SignEncrypt",
			certParams: &certParams,
			cfg: VerifyConfig{
				RootPool:         rootPool,
				IntermediatePool: intermediatePool,
				ValidateFunc: func(pub *tpm2.TPMTPublic) error {
					if !pub.ObjectAttributes.SignEncrypt {
						return errors.New("key does not have SignEncrypt attribute")
					}
					return nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.certParams.Verify(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSimTPMCertifyWithValidation(t *testing.T) {
	t.Run("AK in Owner hiearchy", func(t *testing.T) {
		tpm := setupSimulatedTPM(t)
		certifyingAK, err := tpm.NewAK(AKConfig{Algorithm: algorithm.ECC})
		if err != nil {
			t.Fatalf("NewAK() failed: %v", err)
		}
		defer certifyingAK.Close()
		testCertifyWithValidation(t, tpm, certifyingAK)

	})
	t.Run("AK in Endorsement hiearchy", func(t *testing.T) {
		tpm := setupSimulatedTPM(t)

		ekTemplate := tpmutil.ECCEKTemplate
		ekHandle, err := tpmutil.CreatePrimary(tpm.tpm.(*tpmbase).rwc, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      ekTemplate,
			Auth:          tpmutil.NoAuth,
		})
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}

		parentCfg := &ParentKeyConfig{
			Handle: ekHandle,
			Auth:   tpm2.Policy(ekTemplate.NameAlg, 16 /* nonceSize */, tpmutil.EkPolicyACallback),
		}
		certifyingAK, err := tpm.NewAK(AKConfig{Algorithm: algorithm.ECC, Parent: parentCfg})
		if err != nil {
			t.Fatalf("NewAK() failed: %v", err)
		}
		defer certifyingAK.Close()

		// required to avoid out-of-memory errors
		if err := ekHandle.Close(); err != nil {
			t.Errorf("ekHandle.Close() failed: %v", err)
		}
		testCertifyWithValidation(t, tpm, certifyingAK)
	})
}

func testCertifyWithValidation(t *testing.T, tpm *TPM, certifyingAK *AK) {
	akAttestParams := certifyingAK.AttestationParameters()
	akPub, err := tpmcrypto.PublicKeyECDSA(akAttestParams.Public)
	if err != nil {
		t.Fatalf("PublicKeyECDSA() failed: %v", err)
	}

	tests := []struct {
		name      string
		setupKey  func(t *testing.T) (*CertificationParameters, func())
		validates map[string]bool // which ValidateFunc should pass
	}{
		{
			name: "SRK (Storage Root Key)",
			setupKey: func(t *testing.T) (*CertificationParameters, func()) {
				t.Helper()
				srkHandle, err := tpmutil.GetSRKHandle(tpm.Tpm(), tpmutil.ParentConfig{})
				if err != nil {
					t.Fatalf("GetSRKHandle() failed: %v", err)
				}

				handleClose, err := tpmutil.GetPersistedKeyHandle(tpm.Tpm(), tpmutil.GetPersistedKeyHandleConfig{
					Handle: srkHandle,
				})
				if err != nil {
					t.Fatalf("GetPersistedKeyHandle() failed: %v", err)
				}

				if handleClose.Public() == nil {
					t.Fatalf("handle.Public() is nil")
				}

				certParams, err := certifyingAK.Certify(tpm, CertifyConfig{
					Handle: handleClose,
				})
				if err != nil {
					t.Fatalf("Certify() failed: %v", err)
				}

				return certParams, func() {
					if err := handleClose.Close(); err != nil {
						t.Errorf("CloseHandle() failed: %v", err)
					}
				}
			},
			validates: map[string]bool{
				"SRK":           true,
				"AK":            false,
				"SigningAppKey": false,
				"EK":            false,
			},
		},
		{
			name: "AK (Attestation Key)",
			setupKey: func(t *testing.T) (*CertificationParameters, func()) {
				t.Helper()
				ak2, err := tpm.NewAK(AKConfig{Algorithm: algorithm.ECC})
				if err != nil {
					t.Fatalf("NewAK() failed: %v", err)
				}

				wk, ok := ak2.ak.(*wrappedKey)
				if !ok {
					t.Fatal("failed to access internal wrappedKey")
				}

				certParams, err := certifyingAK.Certify(tpm, CertifyConfig{
					Handle: wk.hnd,
				})
				if err != nil {
					t.Fatalf("Certify() failed: %v", err)
				}

				return certParams, func() {
					if err := ak2.Close(); err != nil {
						t.Errorf("ak.Close() failed: %v", err)
					}
				}
			},
			validates: map[string]bool{
				"SRK":           false,
				"AK":            true,
				"SigningAppKey": false,
			},
		},
		{
			name: "Application Signing Key",
			setupKey: func(t *testing.T) (*CertificationParameters, func()) {
				t.Helper()
				appKey, err := tpm.NewKey(certifyingAK, KeyConfig{KeyType: kty.ECC_P256})
				if err != nil {
					t.Fatalf("NewKey() failed: %v", err)
				}

				wk, ok := appKey.key.(*wrappedKey)
				if !ok {
					t.Fatal("failed to access internal wrappedKey")
				}

				certParams, err := certifyingAK.Certify(tpm, CertifyConfig{
					Handle: wk.hnd,
				})
				if err != nil {
					t.Fatalf("Certify() failed: %v", err)
				}

				return certParams, func() {
					if err := appKey.Close(); err != nil {
						t.Errorf("appKey.Close() failed: %v", err)
					}
				}
			},
			validates: map[string]bool{
				"SRK":           false,
				"AK":            false,
				"SigningAppKey": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certParams, cleanup := tt.setupKey(t)
			defer cleanup()

			validateFuncs := map[string]func(*tpm2.TPMTPublic) error{
				"SRK":           SRKValidateFunc,
				"AK":            AKValidateFunc,
				"SigningAppKey": SigningAppKeyFunc,
			}

			for funcName, validateFunc := range validateFuncs {
				t.Run(funcName, func(t *testing.T) {
					shouldPass := tt.validates[funcName]

					verifyOpts := VerifyConfig{
						Public:       akPub,
						ValidateFunc: validateFunc,
					}

					err := certParams.Verify(verifyOpts)
					if shouldPass && err != nil {
						t.Errorf("Verify() with %s should pass but got error: %v", funcName, err)
					}
					if !shouldPass && err == nil {
						t.Errorf("Verify() with %s should fail but passed", funcName)
					}
				})
			}
		})
	}
}
