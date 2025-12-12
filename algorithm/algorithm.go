package algorithm

import (
	"encoding/json"
)

type Algorithm uint16

func (a Algorithm) String() string {
	v, ok := algs[a]
	if !ok {
		return "UNKNOWN_ALGORITHM"
	}
	return v
}

func (a Algorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// Supported Algorithms.
const (
	Unknown   Algorithm = 0x0000
	RSA       Algorithm = 0x0001
	_3DES     Algorithm = 0x0003 // we use _3DES instead of 3DES to avoid syntax errors
	SHA1      Algorithm = 0x0004
	HMAC      Algorithm = 0x0005
	AES       Algorithm = 0x0006
	MGF1      Algorithm = 0x0007
	KeyedHash Algorithm = 0x0008
	XOR       Algorithm = 0x000A
	SHA256    Algorithm = 0x000B
	SHA384    Algorithm = 0x000C
	SHA512    Algorithm = 0x000D
	Null      Algorithm = 0x0010
	SM3256    Algorithm = 0x0012
	SM4       Algorithm = 0x0013
	RSASSA    Algorithm = 0x0014
	RSAES     Algorithm = 0x0015
	RSAPSS    Algorithm = 0x0016
	OAEP      Algorithm = 0x0017
	ECDSA     Algorithm = 0x0018
	ECDH      Algorithm = 0x0019
	ECDAA     Algorithm = 0x001A
	ECSchnorr Algorithm = 0x001C
	KDF1_56A  Algorithm = 0x0020
	KDF2      Algorithm = 0x0021
	KDF1_108  Algorithm = 0x0022
	ECC       Algorithm = 0x0023
	SymCipher Algorithm = 0x0025
	Camellia  Algorithm = 0x0026
	SHA3_256  Algorithm = 0x0027
	SHA3_384  Algorithm = 0x0028
	SHA3_512  Algorithm = 0x0029
	CMAC      Algorithm = 0x003F
	CTR       Algorithm = 0x0040
	OFB       Algorithm = 0x0041
	CBC       Algorithm = 0x0042
	CFB       Algorithm = 0x0043
	ECB       Algorithm = 0x0044
)

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
var algs = map[Algorithm]string{
	// object types
	RSA: "RSA",
	ECC: "ECC",

	// encryption algs
	RSAES: "RSAES",

	// block ciphers
	_3DES:     "3DES",
	AES:       "AES",
	Camellia:  "Camellia",
	ECB:       "ECB",
	CFB:       "CFB",
	OFB:       "OFB",
	CBC:       "CBC",
	CTR:       "CTR",
	SymCipher: "Symmetric Cipher",
	CMAC:      "CMAC",

	// other ciphers
	XOR:  "XOR",
	Null: "Null Cipher",

	// hash algs
	SHA1:      "SHA-1",
	HMAC:      "HMAC",
	MGF1:      "MGF1",
	KeyedHash: "Keyed Hash",
	SM3256:    "SM3-256",
	SHA256:    "SHA-256",
	SHA384:    "SHA-384",
	SHA512:    "SHA-512",
	SHA3_256:  "SHA3-256",
	SHA3_384:  "SHA3-384",
	SHA3_512:  "SHA3-512",

	// signature algs
	SM4:       "SM4",
	RSASSA:    "RSA-SSA",
	RSAPSS:    "RSA-PSS",
	ECDSA:     "ECDSA",
	ECDAA:     "ECDAA",
	ECSchnorr: "EC-Schnorr",

	// encryption schemes
	OAEP: "OAEP",
	ECDH: "ECDH",

	// key derivation
	KDF1_56A: "KDF1-SP800-56A",
	KDF1_108: "KDF1-SP800-108",
	KDF2:     "KDF2",
}
