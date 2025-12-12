package info

import (
	"reflect"
	"testing"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/kty"
	"github.com/loicsikidi/attest/pcr"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func newBank(alg algorithm.Algorithm, size ...int) pcr.Bank {
	s := 24
	if len(size) > 0 {
		s = size[0]
	}

	slice := make([]uint, s)
	for i := range slice {
		slice[i] = uint(i)
	}
	return pcr.Bank{
		Alg:  alg,
		PCRs: slice,
	}
}

func TestInfo(t *testing.T) {
	simulator, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer simulator.Close()

	got, err := Get(simulator)
	if err != nil {
		t.Fatal(err)
	}

	// expected TPM info for the Microsoft TPM simulator
	expected := &TPMInfo{
		Manufacturer:    GetManufacturerByID(1297303124),
		Vendor:          "xCG fTPM",
		Revision:        "1.54",
		NVMaxBufferSize: 1024,
		NVIndexMaxSize:  2048,
		FirmwareVersion: FirmwareVersion{
			Major: 8215,
			Minor: 1561,
		},
		PcrBanks: []pcr.Bank{
			newBank(algorithm.SHA1),
			newBank(algorithm.SHA256),
			newBank(algorithm.SHA384),
			newBank(algorithm.SHA512),
		},
		KeyTypes: []kty.KeyType{
			kty.RSA_2048,
			kty.RSA_2048WithPSS,
			kty.ECC_P256,
			kty.ECC_P384,
			kty.ECC_P521,
		},
		Algorithms: []algorithm.Algorithm{
			algorithm.RSA,
			algorithm.SHA1,
			algorithm.HMAC,
			algorithm.AES,
			algorithm.MGF1,
			algorithm.KeyedHash,
			algorithm.XOR,
			algorithm.SHA256,
			algorithm.SHA384,
			algorithm.SHA512,
			algorithm.RSASSA,
			algorithm.RSAES,
			algorithm.RSAPSS,
			algorithm.OAEP,
			algorithm.ECDSA,
			algorithm.ECDH,
			algorithm.ECDAA,
			algorithm.ECSchnorr,
			algorithm.KDF1_56A,
			algorithm.KDF1_108,
			algorithm.ECC,
			algorithm.SymCipher,
			algorithm.CMAC,
			algorithm.CTR,
			algorithm.OFB,
			algorithm.CBC,
			algorithm.CFB,
			algorithm.ECB,
		},
	}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("expected %+v, got %+v", expected, got)
	}
}
