package attest

import "github.com/google/go-tpm/tpm2"

var (
	akTemplateRSA = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              false,
			SignEncrypt:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	}
	akTemplateECC = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              false,
			SignEncrypt:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		),
	}
	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	defaultRSASRKTemplate = tpm2.RSASRKTemplate
	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	defaultECCSRKTemplate = tpm2.ECCSRKTemplate
	// RSAEKTemplate contains the TCG reference RSA-2048 EK template.
	defaultRSAEKTemplate = tpm2.RSAEKTemplate
	// ECCEKTemplate contains the TCG reference ECC-P256 EK template.
	defaultECCEKTemplate = tpm2.ECCEKTemplate
	// Basic template for an ECDSA key signing outside-TPM objects. Other
	// fields (NameAlg and Parameters) are populated depending on the key creation options.
	ecdsaKeyTemplate = tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              false,
			SignEncrypt:          true,
		},
	}
	// Basic template for an RSA key signing outside-TPM objects. Other
	// fields (NameAlg and Parameters) are populated depending on the key creation options.
	rsaKeyTemplate = tpm2.TPMTPublic{
		Type: tpm2.TPMAlgRSA,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
	}
)
