package kty

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
)

func TestKeyType_String(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		expected string
	}{
		{"unspecified", UnspecifiedSignAlgorithm, "unspecified"},
		{"RSA_2048", RSA_2048, "RSA_2048_SSA"},
		{"RSA_2048WithPSS", RSA_2048WithPSS, "RSA_2048_PSS"},
		{"RSA_3072", RSA_3072, "RSA_3072_SSA"},
		{"RSA_3072WithPSS", RSA_3072WithPSS, "RSA_3072_PSS"},
		{"RSA_4096", RSA_4096, "RSA_4096_SSA"},
		{"RSA_4096WithPSS", RSA_4096WithPSS, "RSA_4096_PSS"},
		{"ECC_P256", ECC_P256, "ECDSA_P256"},
		{"ECC_P384", ECC_P384, "ECDSA_P384"},
		{"ECC_P521", ECC_P521, "ECDSA_P521"},
		{"unknown", KeyType(999), "unknown(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.keyType.String()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestKeyType_Kind(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		expected tpm2.TPMAlgID
	}{
		{"RSA_2048", RSA_2048, tpm2.TPMAlgRSA},
		{"RSA_2048WithPSS", RSA_2048WithPSS, tpm2.TPMAlgRSA},
		{"RSA_3072", RSA_3072, tpm2.TPMAlgRSA},
		{"RSA_3072WithPSS", RSA_3072WithPSS, tpm2.TPMAlgRSA},
		{"RSA_4096", RSA_4096, tpm2.TPMAlgRSA},
		{"RSA_4096WithPSS", RSA_4096WithPSS, tpm2.TPMAlgRSA},
		{"ECC_P256", ECC_P256, tpm2.TPMAlgECC},
		{"ECC_P384", ECC_P384, tpm2.TPMAlgECC},
		{"ECC_P521", ECC_P521, tpm2.TPMAlgECC},
		{"unknown", KeyType(999), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.keyType.Kind()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestKeyType_Size(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		expected int
	}{
		{"RSA_2048", RSA_2048, 2048},
		{"RSA_2048WithPSS", RSA_2048WithPSS, 2048},
		{"RSA_3072", RSA_3072, 3072},
		{"RSA_3072WithPSS", RSA_3072WithPSS, 3072},
		{"RSA_4096", RSA_4096, 4096},
		{"RSA_4096WithPSS", RSA_4096WithPSS, 4096},
		{"ECC_P256", ECC_P256, 256},
		{"ECC_P384", ECC_P384, 384},
		{"ECC_P521", ECC_P521, 521},
		{"unknown", KeyType(999), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.keyType.Size()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestKeyType_HashAlg(t *testing.T) {
	tests := []struct {
		name      string
		keyType   KeyType
		expected  tpm2.TPMAlgID
		expectErr bool
	}{
		{"RSA_2048", RSA_2048, tpm2.TPMAlgSHA256, false},
		{"RSA_2048WithPSS", RSA_2048WithPSS, tpm2.TPMAlgSHA256, false},
		{"RSA_3072", RSA_3072, tpm2.TPMAlgSHA384, false},
		{"RSA_3072WithPSS", RSA_3072WithPSS, tpm2.TPMAlgSHA384, false},
		{"RSA_4096", RSA_4096, tpm2.TPMAlgSHA512, false},
		{"RSA_4096WithPSS", RSA_4096WithPSS, tpm2.TPMAlgSHA512, false},
		{"ECC_P256", ECC_P256, tpm2.TPMAlgSHA256, false},
		{"ECC_P384", ECC_P384, tpm2.TPMAlgSHA384, false},
		{"ECC_P521", ECC_P521, tpm2.TPMAlgSHA512, false},
		{"unknown", KeyType(999), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.keyType.HashAlg()
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "unknown key type") {
					t.Errorf("error should contain 'unknown key type', got: %v", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func TestKeyType_Hash(t *testing.T) {
	tests := []struct {
		name      string
		keyType   KeyType
		expected  crypto.Hash
		expectErr bool
	}{
		{"RSA_2048", RSA_2048, crypto.SHA256, false},
		{"RSA_2048WithPSS", RSA_2048WithPSS, crypto.SHA256, false},
		{"RSA_3072", RSA_3072, crypto.SHA384, false},
		{"RSA_3072WithPSS", RSA_3072WithPSS, crypto.SHA384, false},
		{"RSA_4096", RSA_4096, crypto.SHA512, false},
		{"RSA_4096WithPSS", RSA_4096WithPSS, crypto.SHA512, false},
		{"ECC_P256", ECC_P256, crypto.SHA256, false},
		{"ECC_P384", ECC_P384, crypto.SHA384, false},
		{"ECC_P521", ECC_P521, crypto.SHA512, false},
		{"unknown", KeyType(999), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.keyType.Hash()
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func TestKeyType_Scheme(t *testing.T) {
	tests := []struct {
		name      string
		keyType   KeyType
		expected  tpm2.TPMAlgID
		expectErr bool
	}{
		{"RSA_2048", RSA_2048, tpm2.TPMAlgRSASSA, false},
		{"RSA_2048WithPSS", RSA_2048WithPSS, tpm2.TPMAlgRSAPSS, false},
		{"RSA_3072", RSA_3072, tpm2.TPMAlgRSASSA, false},
		{"RSA_3072WithPSS", RSA_3072WithPSS, tpm2.TPMAlgRSAPSS, false},
		{"RSA_4096", RSA_4096, tpm2.TPMAlgRSASSA, false},
		{"RSA_4096WithPSS", RSA_4096WithPSS, tpm2.TPMAlgRSAPSS, false},
		{"ECC_P256", ECC_P256, tpm2.TPMAlgECDSA, false},
		{"ECC_P384", ECC_P384, tpm2.TPMAlgECDSA, false},
		{"ECC_P521", ECC_P521, tpm2.TPMAlgECDSA, false},
		{"unknown", KeyType(999), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.keyType.Scheme()
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "unknown key type") {
					t.Errorf("error should contain 'unknown key type', got: %v", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func TestGetSupportedKeyTypes(t *testing.T) {
	sim := tpmtest.OpenSimulator(t)

	supportedTypes, err := GetSupportedKeyTypes(sim)
	if err != nil {
		t.Fatalf("GetSupportedKeyTypes() failed: %v", err)
	}
	if len(supportedTypes) == 0 {
		t.Fatal("supportedTypes should not be empty")
	}

	for _, keyType := range supportedTypes {
		if keyType == UnspecifiedSignAlgorithm {
			t.Errorf("supportedTypes should not contain UnspecifiedSignAlgorithm")
		}
		if keyType < RSA_2048 || keyType > ECC_P521 {
			t.Errorf("keyType %v should be between RSA_2048 and ECC_P521", keyType)
		}
	}
}

func TestGetSupportedKeyTypesAsync(t *testing.T) {
	sim := tpmtest.OpenSimulator(t)

	supportedTypes, err := GetSupportedKeyTypesAsync(sim)
	if err != nil {
		t.Fatalf("GetSupportedKeyTypesAsync() failed: %v", err)
	}
	if len(supportedTypes) == 0 {
		t.Fatal("supportedTypes should not be empty")
	}

	for _, keyType := range supportedTypes {
		if keyType == UnspecifiedSignAlgorithm {
			t.Errorf("supportedTypes should not contain UnspecifiedSignAlgorithm")
		}
		if keyType < RSA_2048 || keyType > ECC_P521 {
			t.Errorf("keyType %v should be between RSA_2048 and ECC_P521", keyType)
		}
	}
}

func TestGetKeyTypeFromPublicKey_RSA(t *testing.T) {
	tests := []struct {
		name     string
		keySize  int
		isPSS    bool
		expected KeyType
	}{
		{"RSA_2048_SSA", 2048, false, RSA_2048},
		{"RSA_2048_PSS", 2048, true, RSA_2048WithPSS},
		{"RSA_3072_SSA", 3072, false, RSA_3072},
		{"RSA_3072_PSS", 3072, true, RSA_3072WithPSS},
		{"RSA_4096_SSA", 4096, false, RSA_4096},
		{"RSA_4096_PSS", 4096, true, RSA_4096WithPSS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := rsa.GenerateKey(rand.Reader, tt.keySize)
			if err != nil {
				t.Fatalf("rsa.GenerateKey() failed: %v", err)
			}

			var opts []crypto.SignerOpts
			if tt.isPSS {
				opts = append(opts, &rsa.PSSOptions{})
			}

			keyType, err := GetKeyTypeFromPublicKey(&privKey.PublicKey, opts...)
			if err != nil {
				t.Fatalf("GetKeyTypeFromPublicKey() failed: %v", err)
			}
			if keyType != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, keyType)
			}
		})
	}
}

func TestGetKeyTypeFromPublicKey_ECDSA(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		expected KeyType
	}{
		{"ECC_P256", elliptic.P256(), ECC_P256},
		{"ECC_P384", elliptic.P384(), ECC_P384},
		{"ECC_P521", elliptic.P521(), ECC_P521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey() failed: %v", err)
			}

			keyType, err := GetKeyTypeFromPublicKey(&privKey.PublicKey)
			if err != nil {
				t.Fatalf("GetKeyTypeFromPublicKey() failed: %v", err)
			}
			if keyType != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, keyType)
			}
		})
	}
}

func TestGetKeyTypeFromPublicKey_UnsupportedTypes(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(t *testing.T)
	}{
		{
			name: "unsupported_rsa_size",
			testFn: func(t *testing.T) {
				privKey, err := rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					t.Fatalf("rsa.GenerateKey() failed: %v", err)
				}

				_, err = GetKeyTypeFromPublicKey(&privKey.PublicKey)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "unsupported RSA key size") {
					t.Errorf("error should contain 'unsupported RSA key size', got: %v", err.Error())
				}
			},
		},
		{
			name: "unsupported_public_key_type",
			testFn: func(t *testing.T) {
				var unsupportedKey struct{}
				_, err := GetKeyTypeFromPublicKey(&unsupportedKey)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "unsupported public key type") {
					t.Errorf("error should contain 'unsupported public key type', got: %v", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.testFn)
	}
}

func TestGetKeyTypeFromPublic(t *testing.T) {
	sim := tpmtest.OpenSimulator(t)

	supportedTypes, err := GetSupportedKeyTypes(sim)
	if err != nil {
		t.Fatalf("GetSupportedKeyTypes() failed: %v", err)
	}
	if len(supportedTypes) == 0 {
		t.Fatal("supportedTypes should not be empty")
	}

	for _, keyType := range supportedTypes {
		t.Run(keyType.String(), func(t *testing.T) {
			info := mapKtyToInfo[keyType]

			grc := tpm2.TestParms{Parameters: info.params}
			if _, err := grc.Execute(sim); err != nil {
				t.Fatalf("TestParms.Execute() failed: %v", err)
			}
		})
	}
}

func TestGetKeyTypeFromPublic_NoMatch(t *testing.T) {
	tpmtPublic := tpm2.TPMTPublic{
		Type: tpm2.TPMAlgRSA,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA1},
					),
				},
				KeyBits: tpm2.TPMKeyBits(1024),
			},
		),
	}

	result, err := GetKeyTypeFromPublic(&tpmtPublic)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if result != UnspecifiedSignAlgorithm {
		t.Errorf("expected UnspecifiedSignAlgorithm, got %v", result)
	}
	if !strings.Contains(err.Error(), "no registered key type matches") {
		t.Errorf("error should contain 'no registered key type matches', got: %v", err.Error())
	}
}
