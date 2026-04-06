package endorsement

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// Template is an helper struct which provides:
// - the NV index pointing to the EK certificate
// - the public area template for this EK (to recreate the EK public key if needed)
type Template struct {
	// Index is the NV index pointing to the EK certificate.
	Index tpm2.TPMHandle

	// Public is the public area template for this EK
	Public tpm2.TPMTPublic

	// originalIsLowRange stores the original low-range status of the template.
	// This is used to preserve the original state when the EK certificate index is updated.
	originalIsLowRange *bool
}

// Type returns the TPM algorithm ID (ECC or RSA) associated with this template.
func (t Template) Type() tpm2.TPMAlgID {
	return t.Public.Type
}

// IsLowRange returns whether this template is for a low-range EK certificate.
func (t Template) IsLowRange() bool {
	if t.originalIsLowRange != nil {
		return *t.originalIsLowRange
	}

	switch t.Index {
	case RSACertIndex, ECCCertIndex:
		return true
	default:
		return false
	}
}

// SetEKCertIndex sets the NV index for the EK certificate and preserves the original low-range status.
func (t *Template) SetEKCertIndex(index tpm2.TPMHandle) {
	isLowRange := t.IsLowRange()
	t.originalIsLowRange = &isLowRange
	t.Index = index
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
	RSAEKTemplate = tpmutil.RSAEKTemplate
	// Low-Range ECC P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.3.4
	ECCEKTemplate = tpmutil.ECCEKTemplate
	// High-Range RSA 2048 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.1
	RSA2048EKTemplate = tpmutil.RSA2048EKTemplate
	// High-Range ECC P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.2
	ECCP256EKTemplate = tpmutil.ECCP256EKTemplate
	// High-Range ECC P384 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.3
	ECCP384EKTemplate = tpmutil.ECCP384EKTemplate
	// High-Range ECC P521 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.4
	ECCP521EKTemplate = tpmutil.ECCP521EKTemplate
	// High-Range ECC SM2 P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.5
	ECCSM2P256EKTemplate = tpmutil.ECCSM2P256EKTemplate
	// High-Range RSA 3072 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.6
	RSA3072EKTemplate = tpmutil.RSA3072EKTemplate
	// High-Range RSA 4096 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.7
	RSA4096EKTemplate = tpmutil.RSA4096EKTemplate
)
