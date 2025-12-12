// This file indicates if (common) key types are supported by the TPM.
//
// Important: currently, the focus is dedicated to asymmetric keys.
//
// Note: as far as I know, TCG does not recommand an approach to determine this information.
// We can either rely on TPM2_Capabilities (i.e. TPM2_CAP_ALGS) or use TPM2_TestParms.
//
// We choose TPM2_TestParms approach because it's an explicit proof.
//
// Tip: is recommended to cache GetSupportedKeyTypes() result
// to avoid multiple calls to the TPM, which can be expensive.
package kty

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	tpmcrypto "github.com/loicsikidi/go-tpm-kit/tpmcrypto"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type KeyType int

const (
	UnspecifiedSignAlgorithm KeyType = iota
	// RSASSA-PKCS1-v1_5 key and a SHA256 digest.
	RSA_2048
	// RSASSA-PSS key with a SHA256 digest.
	RSA_2048WithPSS
	// RSASSA-PKCS1-v1_5 key and a SHA384 digest.
	RSA_3072
	// RSASSA-PSS key with a SHA384 digest.
	RSA_3072WithPSS
	// RSASSA-PKCS1-v1_5 key and a SHA512 digest.
	RSA_4096
	// RSASSA-PSS key with a SHA512 digest.
	RSA_4096WithPSS
	// ECDSA on the NIST P-256 curve with a SHA256 digest.
	ECC_P256
	// ECDSA on the NIST P-384 curve with a SHA384 digest.
	ECC_P384
	// ECDSA on the NIST P-521 curve with a SHA512 digest.
	ECC_P521
)

// String returns a string representation of s.
func (k KeyType) String() string {
	switch k {
	case UnspecifiedSignAlgorithm:
		return "unspecified"
	case RSA_2048:
		return "RSA_2048_SSA"
	case RSA_2048WithPSS:
		return "RSA_2048_PSS"
	case RSA_3072:
		return "RSA_3072_SSA"
	case RSA_3072WithPSS:
		return "RSA_3072_PSS"
	case RSA_4096:
		return "RSA_4096_SSA"
	case RSA_4096WithPSS:
		return "RSA_4096_PSS"
	case ECC_P256:
		return "ECDSA_P256"
	case ECC_P384:
		return "ECDSA_P384"
	case ECC_P521:
		return "ECDSA_P521"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
}

type info struct {
	curveID tpm2.TPMECCCurve // specific to ECC keys
	hashAlg tpm2.TPMIAlgHash
	kind    tpm2.TPMAlgID
	params  tpm2.TPMTPublicParms // this field is initialized by init() function
	scheme  tpm2.TPMAlgID
	size    int
}

var mapKtyToInfo = map[KeyType]info{
	RSA_2048:        {kind: tpm2.TPMAlgRSA, scheme: tpm2.TPMAlgRSASSA, hashAlg: tpm2.TPMAlgSHA256, size: 2048},
	RSA_2048WithPSS: {kind: tpm2.TPMAlgRSA, scheme: tpm2.TPMAlgRSAPSS, hashAlg: tpm2.TPMAlgSHA256, size: 2048},
	RSA_3072:        {kind: tpm2.TPMAlgRSA, scheme: tpm2.TPMAlgRSASSA, hashAlg: tpm2.TPMAlgSHA384, size: 3072},
	RSA_3072WithPSS: {kind: tpm2.TPMAlgRSA, scheme: tpm2.TPMAlgRSAPSS, hashAlg: tpm2.TPMAlgSHA384, size: 3072},
	RSA_4096:        {kind: tpm2.TPMAlgRSA, scheme: tpm2.TPMAlgRSASSA, hashAlg: tpm2.TPMAlgSHA512, size: 4096},
	RSA_4096WithPSS: {kind: tpm2.TPMAlgRSA, scheme: tpm2.TPMAlgRSAPSS, hashAlg: tpm2.TPMAlgSHA512, size: 4096},
	ECC_P256:        {kind: tpm2.TPMAlgECC, scheme: tpm2.TPMAlgECDSA, hashAlg: tpm2.TPMAlgSHA256, size: 256, curveID: tpm2.TPMECCNistP256},
	ECC_P384:        {kind: tpm2.TPMAlgECC, scheme: tpm2.TPMAlgECDSA, hashAlg: tpm2.TPMAlgSHA384, size: 384, curveID: tpm2.TPMECCNistP384},
	ECC_P521:        {kind: tpm2.TPMAlgECC, scheme: tpm2.TPMAlgECDSA, hashAlg: tpm2.TPMAlgSHA512, size: 521, curveID: tpm2.TPMECCNistP521},
}

func init() {
	for kty, i := range mapKtyToInfo {
		prev := mapKtyToInfo[kty]
		prev.params = must(getParams(kty, i))
		mapKtyToInfo[kty] = prev
	}
}

// panic should never happen, knowing that mapKtyToParams is privately initialized
func must(params *tpm2.TPMTPublicParms, err error) tpm2.TPMTPublicParms {
	if err != nil {
		panic(fmt.Sprintf("failed to get key parameters: %v", err))
	}
	return *params
}

func getParams(kty KeyType, i info) (*tpm2.TPMTPublicParms, error) {
	var pubParams *tpm2.TPMTPublicParms
	switch kty {
	case RSA_2048, RSA_3072, RSA_4096, RSA_2048WithPSS, RSA_3072WithPSS, RSA_4096WithPSS:
		params, err := tpmcrypto.NewRSASigKeyParameters(i.size, i.scheme)
		if err != nil {
			return nil, err
		}
		pubParams = &tpm2.TPMTPublicParms{
			Type:       tpm2.TPMAlgRSA,
			Parameters: *params,
		}
	case ECC_P256, ECC_P384, ECC_P521:
		params, err := tpmcrypto.NewECCSigKeyParameters(i.curveID)
		if err != nil {
			return nil, err
		}
		pubParams = &tpm2.TPMTPublicParms{
			Type:       tpm2.TPMAlgECC,
			Parameters: *params,
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
	return pubParams, nil
}

// GetSupportedKeyTypes returns the list of supported KeyType by the TPM.
//
// Note: the returned slice is sorted in ascending order.
func GetSupportedKeyTypes(t transport.TPM) ([]KeyType, error) {
	supported := []KeyType{}
	for kty, info := range mapKtyToInfo {
		grc := tpm2.TestParms{Parameters: info.params}
		_, err := grc.Execute(t)
		if err == nil {
			supported = append(supported, kty)
			continue
		}
		if !errors.Is(err, tpm2.TPMRCValue) && !errors.Is(err, tpm2.TPMRCHash) {
			return nil, fmt.Errorf("failed tpm2.TestParams for key type %s: %w", kty, err)
		}
	}
	slices.Sort(supported)
	return supported, nil
}

// Experimental: this function may be removed in the future.
//
// Note: the returned slice is sorted in ascending order.
func GetSupportedKeyTypesAsync(t transport.TPM) ([]KeyType, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tpmMu sync.Mutex // Mutex to serialize TPM access
	var supported []KeyType
	errCh := make(chan error, 1)

	for kty, i := range mapKtyToInfo {
		wg.Add(1)
		go func(kty KeyType, i info) {
			defer wg.Done()

			grc := tpm2.TestParms{Parameters: i.params}

			// Serialize TPM access to prevent data races
			tpmMu.Lock()
			_, err := grc.Execute(t)
			tpmMu.Unlock()

			if err == nil {
				mu.Lock()
				supported = append(supported, kty)
				mu.Unlock()
				return
			}
			if !errors.Is(err, tpm2.TPMRCValue) {
				errCh <- fmt.Errorf("failed tpm2.TestParams for key type %s: %w", kty, err)
				return
			}
		}(kty, i)
	}

	wg.Wait()
	close(errCh)

	if err := <-errCh; err != nil {
		return nil, err
	}
	sort.Slice(supported, func(i, j int) bool {
		return supported[i] < supported[j]
	})
	return supported, nil
}

func (k KeyType) Kind() tpm2.TPMAlgID {
	info, ok := mapKtyToInfo[k]
	if !ok {
		return 0
	}
	return info.kind
}

func (k KeyType) Size() int {
	info, ok := mapKtyToInfo[k]
	if !ok {
		return 0
	}
	return info.size
}

func (k KeyType) HashAlg() (tpm2.TPMAlgID, error) {
	info, ok := mapKtyToInfo[k]
	if !ok {
		return 0, fmt.Errorf("unknown key type: %s", k)
	}
	return info.hashAlg, nil
}

func (k KeyType) Hash() (crypto.Hash, error) {
	hashAlg, err := k.HashAlg()
	if err != nil {
		return 0, err
	}
	return hashAlg.Hash()
}
func (k KeyType) Scheme() (tpm2.TPMAlgID, error) {
	info, ok := mapKtyToInfo[k]
	if !ok {
		return 0, fmt.Errorf("unknown key type: %s", k)
	}
	return info.scheme, nil
}

func GetKeyTypeFromPublic(pub *tpm2.TPMTPublic) (KeyType, error) {
	sigScheme, sigHash, err := tpmcrypto.GetSigSchemeAndHashFromPublic(*pub)
	if err != nil {
		return UnspecifiedSignAlgorithm, err
	}
	for kty, info := range mapKtyToInfo {
		if info.kind == pub.Type && info.scheme == sigScheme && info.hashAlg == sigHash {
			return kty, nil
		}
		continue
	}
	return UnspecifiedSignAlgorithm, errors.New("no registered key type matches the given TPMT_PUBLIC")
}

func GetKeyTypeFromPublicKey(pub crypto.PublicKey, opts ...crypto.SignerOpts) (KeyType, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return getRSAKeyType(p, opts...)
	case *ecdsa.PublicKey:
		switch p.Curve.Params().Name {
		case "P-256":
			return ECC_P256, nil
		case "P-384":
			return ECC_P384, nil
		case "P-521":
			return ECC_P521, nil
		default:
			return UnspecifiedSignAlgorithm, fmt.Errorf("unsupported ECC curve: %s", p.Curve.Params().Name)
		}
	default:
		return UnspecifiedSignAlgorithm, fmt.Errorf("unsupported public key type: %T", p)

	}
}

func getRSAKeyType(pub *rsa.PublicKey, opts ...crypto.SignerOpts) (KeyType, error) {
	isPSS := false
	if len(opts) > 0 {
		if _, ok := opts[0].(*rsa.PSSOptions); ok {
			isPSS = true
		}
	}
	switch pub.Size() * 8 {
	case 2048:
		if isPSS {
			return RSA_2048WithPSS, nil
		}
		return RSA_2048, nil
	case 3072:
		if isPSS {
			return RSA_3072WithPSS, nil
		}
		return RSA_3072, nil
	case 4096:
		if isPSS {
			return RSA_4096WithPSS, nil
		}
		return RSA_4096, nil
	default:
		return UnspecifiedSignAlgorithm, fmt.Errorf("unsupported RSA key size: %d", pub.Size())
	}
}
