package endorsement

import (
	"github.com/google/go-tpm/tpm2"
)

var PublicTemplateByNVIndex = map[tpm2.TPMHandle]tpm2.TPMTPublic{
	ECCCertIndex:        ECCEKTemplate,
	ECCP256CertIndex:    ECCP256EKTemplate,
	ECCP384CertIndex:    ECCP384EKTemplate,
	ECCP521CertIndex:    ECCP521EKTemplate,
	ECCSM2P256CertIndex: ECCSM2P256EKTemplate,
	RSACertIndex:        RSAEKTemplate,
	RSA2048CertIndex:    RSA2048EKTemplate,
	RSA3072CertIndex:    RSA3072EKTemplate,
	RSA4096CertIndex:    RSA4096EKTemplate,
}

type Template struct {
	// Index is the NV index pointing to the EK certificate.
	Index tpm2.TPMHandle
	// Public is the public area template for this EK
	Public tpm2.TPMTPublic
}

// Type returns the TPM algorithm ID (ECC or RSA) associated with this template.
func (t Template) Type() tpm2.TPMAlgID {
	return t.Public.Type
}

// Predefined EK templates.
var (
	TemplateRSA = Template{
		Index:  RSACertIndex,
		Public: RSAEKTemplate,
	}
	TemplateECC = Template{
		Index:  ECCCertIndex,
		Public: ECCEKTemplate,
	}
	TemplateRSA2048 = Template{
		Index:  RSA2048CertIndex,
		Public: RSA2048EKTemplate,
	}
	TemplateECCP256 = Template{
		Index:  ECCP256CertIndex,
		Public: ECCP256EKTemplate,
	}
	TemplateECCP384 = Template{
		Index:  ECCP384CertIndex,
		Public: ECCP384EKTemplate,
	}
	TemplateECCP521 = Template{
		Index:  ECCP521CertIndex,
		Public: ECCP521EKTemplate,
	}
	TemplateECCSM2P256 = Template{
		Index:  ECCSM2P256CertIndex,
		Public: ECCSM2P256EKTemplate,
	}
	TemplateRSA3072 = Template{
		Index:  RSA3072CertIndex,
		Public: RSA3072EKTemplate,
	}
	TemplateRSA4096 = Template{
		Index:  RSA4096CertIndex,
		Public: RSA4096EKTemplate,
	}
)

var TemplatesByType = map[tpm2.TPMAlgID][]Template{
	tpm2.TPMAlgRSA: {
		TemplateRSA,
		TemplateRSA2048,
		TemplateRSA3072,
		TemplateRSA4096,
	},
	tpm2.TPMAlgECC: {
		TemplateECC,
		TemplateECCP256,
		TemplateECCP384,
		TemplateECCP521,
		TemplateECCSM2P256,
	},
}

// NV Indices for EK Certificates as per TCG EK Credential Profile v2.6
var (
	// Low-Range RSA 2048
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.4
	RSACertIndex tpm2.TPMHandle = 0x1C00002
	// Low-Range ECC NIST P256
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.4
	ECCCertIndex tpm2.TPMHandle = 0x1C0000A
	// High-Range RSA 2048
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	RSA2048CertIndex tpm2.TPMHandle = 0x01C00012
	// High-Range ECC NIST P256
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCP256CertIndex tpm2.TPMHandle = 0x01C00014
	// ECC NIST P384
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCP384CertIndex tpm2.TPMHandle = 0x01C00016
	// ECC NIST P521
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCP521CertIndex tpm2.TPMHandle = 0x01C00018
	// ECC SM2 P256
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCSM2P256CertIndex tpm2.TPMHandle = 0x01C0001A
	// RSA 3072
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	RSA3072CertIndex tpm2.TPMHandle = 0x01C0001C
	// RSA 4096
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	RSA4096CertIndex tpm2.TPMHandle = 0x01C0001E
)

// Predefined EK templates (public area).
var (
	// Low-Range RSA 2048 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.3.3
	RSAEKTemplate = tpm2.RSAEKTemplate
	// Low-Range ECC P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.3.4
	ECCEKTemplate = tpm2.ECCEKTemplate
	// High-Range RSA 2048 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.1
	RSA2048EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SHA256
				0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9,
				0x39, 0x06, 0xF7, 0xA3, 0x34, 0x24,
				0x14, 0xEF, 0xCF, 0xB3, 0xA3, 0x85,
				0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
				0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0,
				0xB7, 0xA0,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
	}
	// High-Range ECC P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.2
	ECCP256EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SHA256
				0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9,
				0x39, 0x06, 0xF7, 0xA3, 0x34, 0x24,
				0x14, 0xEF, 0xCF, 0xB3, 0xA3, 0x85,
				0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
				0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0,
				0xB7, 0xA0,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
	}
	// High-Range ECC P384 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.3
	ECCP384EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SHA384
				0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A,
				0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
				0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41,
				0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
				0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4,
				0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
				0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F,
				0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP384,
			},
		),
	}
	// High-Range ECC P521 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.4
	ECCP521EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA512,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SHA512
				0xB8, 0x22, 0x1C, 0xA6, 0x9E, 0x85,
				0x50, 0xA4, 0x91, 0x4D, 0xE3, 0xFA,
				0xA6, 0xA1, 0x8C, 0x07, 0x2C, 0xC0,
				0x12, 0x08, 0x07, 0x3A, 0x92, 0x8D,
				0x5D, 0x66, 0xD5, 0x9E, 0xF7, 0x9E,
				0x49, 0xA4, 0x29, 0xC4, 0x1A, 0x6B,
				0x26, 0x95, 0x71, 0xD5, 0x7E, 0xDB,
				0x25, 0xFB, 0xDB, 0x18, 0x38, 0x42,
				0x56, 0x08, 0xB4, 0x13, 0xCD, 0x61,
				0x6A, 0x5F, 0x6D, 0xB5, 0xB6, 0x07,
				0x1A, 0xF9, 0x9B, 0xEA,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP521,
			},
		),
	}
	// High-Range ECC SM2 P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.5
	ECCSM2P256EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSM3256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SM3-256
				0x16, 0x78, 0x60, 0xA3, 0x5F, 0x2C,
				0x5C, 0x35, 0x67, 0xF9, 0xC9, 0x27,
				0xAC, 0x56, 0xC0, 0x32, 0xF3, 0xB3,
				0xA6, 0x46, 0x2F, 0x8D, 0x03, 0x79,
				0x98, 0xE7, 0xA1, 0x0F, 0x77, 0xFA,
				0x45, 0x4A,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgSM4,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgSM4,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgSM4,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCSM2P256,
			},
		),
	}
	// High-Range RSA 3072 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.6
	RSA3072EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SHA384
				0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A,
				0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
				0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41,
				0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
				0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4,
				0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
				0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F,
				0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 3072,
			},
		),
	}
	// High-Range RSA 4096 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.7
	RSA4096EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				// PolicyB SHA384
				0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A,
				0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
				0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41,
				0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
				0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4,
				0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
				0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F,
				0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 4096,
			},
		),
	}
)
