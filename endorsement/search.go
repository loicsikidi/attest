package endorsement

import (
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/attest/info"
	"github.com/loicsikidi/attest/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

var (
	ErrUntrustedEK    = fmt.Errorf("untrusted endorsement key")
	ErrEKCertNotFound = fmt.Errorf("endorsement certificate not found")
)

// GetCertConfig configures the behavior of [GetCertificate].
type GetCertConfig struct {
	// Template specifies which EK template to use.
	Template Template
	// SkipPublicMatching skips generating the EK public key from the template.
	//
	// Notes:
	//   * Generating the EK public key can be time-consuming as it involves CreatePrimary operations.
	//   * It is secure to skip this step if proof of possession is performed indirectly
	//     later in the attestation flow (e.g., via MakeCredential/ActivateCredential).
	//     The MakeCredential challenge ensures that the TPM possesses the private key
	//     corresponding to the EK certificate, providing cryptographic proof without
	//     needing to generate the EK public key upfront.
	SkipPublicMatching bool
	// SkipCheck skips running [EK.Check] on the certificate found.
	SkipCheck bool
}

// CheckAndSetDefault validates and sets default values for GetConfig.
func (c *GetCertConfig) CheckAndSetDefault() error {
	if c.Template.Index == 0 {
		return fmt.Errorf("template index cannot be 0")
	}
	if c.Template.Public.Type == tpm2.TPMAlgNull {
		return fmt.Errorf("template public type cannot be TPMAlgNull")
	}
	if c.SkipPublicMatching {
		// If skipping public matching, also skip check as it requires the public key.
		c.SkipCheck = true
	}
	return nil
}

// GetCertificate retrieves a specific EK certificate from the TPM based on the provided template.
// It returns an [EK] structure containing the certificate and optionally its public key.
// If EK certificate chains are available in TPM NVRAM, they will be added to the EK structure.
//
// Example:
//
//	// Get RSA EK certificate with full validation
//	ek, err := GetCertificate(tpm, GetConfig{
//		Template: Template{
//			Index:  RSACertIndex,
//			Public: RSAEKTemplate,
//		},
//	})
//
//	// Get ECC EK certificate without validation
//	ek, err := GetCertificate(tpm, GetConfig{
//		Template: Template{
//			Index:  ECCCertIndex,
//			Public: ECCEKTemplate,
//		},
//		SkipCheck: true,
//	})
func GetCertificate(tpm transport.TPM, cfg GetCertConfig) (EK, error) {
	if err := cfg.CheckAndSetDefault(); err != nil {
		return EK{}, fmt.Errorf("invalid GetCertConfig: %w", err)
	}

	ek := EK{Template: cfg.Template}

	cert, err := ReadEKCertFromNVRAM(tpm, cfg.Template.Index)
	if err != nil {
		wrap := fmt.Errorf("failed to read EK certificate from NV index %X: %w", cfg.Template.Index, err)
		return EK{}, fmt.Errorf("%w: %w", ErrEKCertNotFound, wrap)
	}
	ek.Certificate = cert

	if !cfg.SkipPublicMatching {
		pub, err := getOrCreateEKPublic(tpm, cfg.Template.Public.Type, cfg.Template)
		if err != nil {
			return EK{}, fmt.Errorf("failed to get EK public key: %w", err)
		}
		ek.Public = pub
	}

	if !cfg.SkipCheck {
		if err := ek.Check(); err != nil {
			wrap := fmt.Errorf("EK certificate validation failed for NV index %X: %w", cfg.Template.Index, err)
			return EK{}, fmt.Errorf("%w: %w", ErrUntrustedEK, wrap)
		}
	}

	// Retrieve TPM info to check for EK certificate chains
	tpmInfo, err := info.Get(tpm)
	if err != nil {
		return EK{}, fmt.Errorf("failed to get TPM info: %w", err)
	}

	if tpmInfo.HasEKCertChains() {
		ek.AddChain(tpmInfo.EKCertChains)
	}

	return ek, nil
}

// GetConfig configures the behavior of [Get].
type GetConfig struct {
	// Template specifies which EK template to use.
	Template Template
	// Info contains TPM information required to produce the EK certificate URL.
	Info info.TPMInfo
}

// CheckAndSetDefault validates and sets default values for GetConfig.
func (c *GetConfig) CheckAndSetDefault() error {
	if c.Template.Index == 0 {
		return fmt.Errorf("template index cannot be 0")
	}
	if c.Template.Public.Type == tpm2.TPMAlgNull {
		return fmt.Errorf("template public type cannot be TPMAlgNull")
	}
	return nil
}

// Get retrieves the endorsement key from the TPM based on the provided template.
//
// Note: this function does NOT attempt to read the EK certificate from NVRAM.
// Use it ONLY if you need to create an EK structure without certificate.
func Get(tpm transport.TPM, cfg GetConfig) (EK, error) {
	if err := cfg.CheckAndSetDefault(); err != nil {
		return EK{}, fmt.Errorf("invalid GetConfig: %w", err)
	}

	ek := EK{Template: cfg.Template}

	pub, err := getOrCreateEKPublic(tpm, cfg.Template.Public.Type, cfg.Template)
	if err != nil {
		return EK{}, fmt.Errorf("failed to get EK public key: %w", err)
	}
	ek.Public = pub

	pubKey, err := ek.PublicKey()
	if err != nil {
		return EK{}, fmt.Errorf("failed to get EK public key: %w", err)
	}
	ek.CertificateURL = EkCertURL(pubKey, cfg.Info.Manufacturer.ASCII)

	return ek, nil

}

// SearchCertConfig configures the behavior of [SearchCertificates].
type SearchCertConfig struct {
	// KeyType filters search by algorithm type. If 0, searches all key types.
	KeyType tpm2.TPMAlgID
	// SkipPublicMatching skips generating the EK public key from the template.
	//
	// Notes:
	//   * Generating the EK public key can be time-consuming as it involves CreatePrimary operations.
	//   * It is secure to skip this step if proof of possession is performed indirectly
	//     later in the attestation flow (e.g., via MakeCredential/ActivateCredential).
	//     The MakeCredential challenge ensures that the TPM possesses the private key
	//     corresponding to the EK certificate, providing cryptographic proof without
	//     needing to generate the EK public key upfront.
	SkipPublicMatching bool
	// SkipCheck skips running [EK.Check] on each certificate found.
	SkipCheck bool
	// Info contains TPM information used for fallback certificate URL generation.
	//
	// Notes:
	//   * the field is required only if you want to populate the EK.CertificateURL field when the certificate is not present.
	//   * this field cannot be used with SkipPublicMatching=true, as generating the certificate URL requires the EK public key.
	Info *info.TPMInfo
}

// CheckAndSetDefault validates and sets default values for SearchConfig.
func (c *SearchCertConfig) CheckAndSetDefault() error {
	if c.KeyType != 0 && c.KeyType != tpm2.TPMAlgRSA && c.KeyType != tpm2.TPMAlgECC {
		return fmt.Errorf("unsupported key type: %X", c.KeyType)
	}
	if c.SkipPublicMatching {
		// If skipping public matching, also skip check as it requires the public key.
		c.SkipCheck = true
	}
	if c.Info != nil && c.SkipPublicMatching {
		return fmt.Errorf("cannot use Info with SkipPublicMatching=true")
	}
	return nil
}

// SearchCertificates searches for EK certificates in the TPM.
// It returns a list of [EK] structures containing certificates and their public keys.
//
// Example:
//
//	// Search all EK certificates with full validation
//	eks, err := SearchCertificates(tpm)
//
//	// Search only RSA certificates without validation
//	eks, err := SearchCertificates(tpm, SearchConfig{
//		KeyType: tpm2.TPMAlgRSA,
//		SkipCheck: true,
//	})
func SearchCertificates(tpm transport.TPM, optionalCfg ...SearchCertConfig) ([]EK, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	var keyTypes []tpm2.TPMAlgID
	if cfg.KeyType == 0 {
		keyTypes = []tpm2.TPMAlgID{tpm2.TPMAlgRSA, tpm2.TPMAlgECC}
	} else {
		keyTypes = []tpm2.TPMAlgID{cfg.KeyType}
	}

	var results []EK
	for _, keyType := range keyTypes {
		templates := SearchAvailableCertificates(tpm, keyType)

		for _, template := range templates {
			ek, err := GetCertificate(tpm, GetCertConfig{
				Template:           template,
				SkipPublicMatching: cfg.SkipPublicMatching,
				SkipCheck:          cfg.SkipCheck,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to get certificate for template %X: %w", template.Index, err)
			}

			results = append(results, ek)
		}
	}

	return results, nil
}

// getOrCreateEKPublic tries to read the EK public key from persistent handle first,
// then falls back to CreatePrimary if not found.
func getOrCreateEKPublic(tpm transport.TPM, alg tpm2.TPMAlgID, template Template) (*tpm2.TPMTPublic, error) {
	handle, ok := HandleByType[alg]
	if ok {
		rsp, err := tpm2.ReadPublic{
			ObjectHandle: handle,
		}.Execute(tpm)
		if err == nil {
			pub, err := rsp.OutPublic.Contents()
			if err == nil && isTemplateMatch(pub, template) {
				return pub, nil
			}
		}
	}

	// Fallback: create the EK using the template
	ekHandle, err := tpmutil.CreatePrimary(tpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		Auth:          tpmutil.NoAuth,
		InPublic:      template.Public,
	})
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary failed: %w", err)
	}
	defer ekHandle.Handle() //nolint:errcheck

	return ekHandle.Public(), nil
}

// isTemplateMatch verifies that the public key matches the expected template.
func isTemplateMatch(pub *tpm2.TPMTPublic, template Template) bool {
	if pub.Type != template.Public.Type {
		return false
	}

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		pubParams, err := pub.Parameters.RSADetail()
		if err != nil {
			return false
		}
		templateParams, err := template.Public.Parameters.RSADetail()
		if err != nil {
			return false
		}
		return pubParams.KeyBits == templateParams.KeyBits

	case tpm2.TPMAlgECC:
		pubParams, err := pub.Parameters.ECCDetail()
		if err != nil {
			return false
		}
		templateParams, err := template.Public.Parameters.ECCDetail()
		if err != nil {
			return false
		}
		return pubParams.CurveID == templateParams.CurveID

	default:
		return false
	}
}

// SearchAvailableCertificates searches for available EK certificates in the TPM.
//
// How it works? Each EK certificate is stored in a well-known NV index. The function
// checks each known NV index for data presence.
//
// It returns a slice of [Template] in order to find easily the corresponding EK certificates (i.e. Index)
// and public template (i.e., Public) to be able to recreate the EK public key if needed.
//
// The optional kty parameter filters results by key algorithm:
//   - If not provided, searches all key types
//   - If set to [tpm2.TPMAlgRSA] or [tpm2.TPMAlgECC], searches only that key type
//
// Example:
//
//	// Search all key types
//	templates := SearchAvailableCertificates(tpm)
//
//	// Search only RSA keys
//	templates := SearchAvailableCertificates(tpm, tpm2.TPMAlgRSA)
func SearchAvailableCertificates(tpm transport.TPM, optionalKty ...tpm2.TPMAlgID) []Template {
	var results []Template

	// Get optional key type filter
	keyType := utils.OptionalArg(optionalKty)
	filterByKeyType := slices.Contains([]tpm2.TPMAlgID{tpm2.TPMAlgRSA, tpm2.TPMAlgECC}, keyType)

	var templatesToCheck []Template
	if filterByKeyType {
		templatesToCheck = TemplatesByType[keyType]
	} else {
		for _, templates := range TemplatesByType {
			templatesToCheck = append(templatesToCheck, templates...)
		}
	}

	// Check each template's NV index for data
	for _, template := range templatesToCheck {
		_, err := tpm2.NVReadPublic{
			NVIndex: template.Index,
		}.Execute(tpm)

		if err == nil {
			results = append(results, template)
		}
	}

	return results
}

// SearchPersistedTemplates searches for EK keys that are persisted in the TPM.
// TCG-compliant TPMs typically persist EKs at well-known handles:
//   - RSA EK at handle 0x81010001 (i.e., [RSAHandle])
//   - ECC EK at handle 0x81010002 (i.e., [ECCHandle])
//
// It returns a slice of corresponding [Template] to find easily to corresponding
// EK certificates in NVRAM.
//
// Example:
//
//	templates := SearchPersistedTemplates(tpm)
func SearchPersistedTemplates(tpm transport.TPM) []Template {
	var results []Template

	for _, handle := range HandleByType {
		rsp, err := tpm2.ReadPublic{
			ObjectHandle: handle,
		}.Execute(tpm)
		if err != nil {
			continue
		}
		pub, err := rsp.OutPublic.Contents()
		if err != nil {
			continue
		}
		for _, template := range TemplatesByType[pub.Type] {
			if isTemplateMatch(pub, template) {
				results = append(results, template)
				break
			}
		}
	}
	return results
}

// GetTemplate retrieves the EK template matching the provided public key.
// It returns an error if no matching template is found.
//
// Example:
//
//	template, err := GetTemplate(ek.Public)
//	if err != nil {
//		// handle error
//	}
//
// EXPERIMENTAL: this function may be changed or removed in future releases.
func GetTemplate(pub *tpm2.TPMTPublic) (*Template, error) {
	templates, ok := TemplatesByType[pub.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported public key type: %X", pub.Type)
	}
	for _, template := range templates {
		if isTemplateMatch(pub, template) {
			return &template, nil
		}
	}
	return nil, fmt.Errorf("no matching template found for public key")
}
