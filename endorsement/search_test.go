package endorsement

import (
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestSearchAvailableCertificates_Integration(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	t.Run("search all key types", func(t *testing.T) {
		results := SearchAvailableCertificates(tpm)

		if len(results) == 0 {
			t.Error("SearchAvailableCertificates() returned no templates")
		}

		// Verify each result has valid index and template
		for i, tmpl := range results {
			if tmpl.Index == 0 {
				t.Errorf("Template[%d] has invalid index: 0", i)
			}
			if tmpl.Public.Type == tpm2.TPMAlgNull {
				t.Errorf("Template[%d] has invalid type: TPMAlgNull", i)
			}
		}
	})

	t.Run("search RSA only", func(t *testing.T) {
		results := SearchAvailableCertificates(tpm, tpm2.TPMAlgRSA)

		if len(results) == 0 {
			t.Error("SearchAvailableCertificates() returned no templates")
		}

		// Should return only RSA templates
		for i, tmpl := range results {
			if tmpl.Public.Type != tpm2.TPMAlgRSA {
				t.Errorf("Template[%d] has type %v, expected TPMAlgRSA", i, tmpl.Public.Type)
			}
		}
	})

	t.Run("search ECC only", func(t *testing.T) {
		results := SearchAvailableCertificates(tpm, tpm2.TPMAlgECC)

		if len(results) == 0 {
			t.Error("SearchAvailableCertificates() returned no templates")
		}

		// Should return only ECC templates
		for i, tmpl := range results {
			if tmpl.Public.Type != tpm2.TPMAlgECC {
				t.Errorf("Template[%d] has type %v, expected TPMAlgECC", i, tmpl.Public.Type)
			}
		}
	})
}

func TestGetCertificate_Integration(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	t.Run("get RSA certificate with validation", func(t *testing.T) {
		templates := SearchAvailableCertificates(tpm, tpm2.TPMAlgRSA)
		if len(templates) == 0 {
			t.Skip("No RSA EK certificate available on this TPM")
		}

		ek, err := GetCertificate(tpm, GetCertConfig{
			Template: templates[0],
		})
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}

		if ek.Certificate == nil {
			t.Error("EK has nil certificate")
		}
		if ek.Public == nil {
			t.Error("EK has nil public key")
		}
		if ek.Public != nil && ek.Public.Type != tpm2.TPMAlgRSA {
			t.Errorf("EK has type %v, expected TPMAlgRSA", ek.Public.Type)
		}
	})

	t.Run("get ECC certificate with validation", func(t *testing.T) {
		templates := SearchAvailableCertificates(tpm, tpm2.TPMAlgECC)
		if len(templates) == 0 {
			t.Skip("No ECC EK certificate available on this TPM")
		}

		ek, err := GetCertificate(tpm, GetCertConfig{
			Template: templates[0],
		})
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}

		if ek.Certificate == nil {
			t.Error("EK has nil certificate")
		}
		if ek.Public == nil {
			t.Error("EK has nil public key")
		}
		if ek.Public != nil && ek.Public.Type != tpm2.TPMAlgECC {
			t.Errorf("EK has type %v, expected TPMAlgECC", ek.Public.Type)
		}
	})

	t.Run("skip public matching", func(t *testing.T) {
		templates := SearchAvailableCertificates(tpm)
		if len(templates) == 0 {
			t.Skip("No EK certificates available on this TPM")
		}

		ek, err := GetCertificate(tpm, GetCertConfig{
			Template:           templates[0],
			SkipPublicMatching: true,
		})
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}

		if ek.Certificate == nil {
			t.Error("EK has nil certificate")
		}
		if ek.Public != nil {
			t.Error("EK has public key when SkipPublicMatching is true")
		}
	})

	t.Run("error on invalid template", func(t *testing.T) {
		_, err := GetCertificate(tpm, GetCertConfig{
			Template: Template{},
		})
		if err == nil {
			t.Error("GetCertificate() should fail with empty template")
		}
	})

	t.Run("check fails when public key differs from certificate", func(t *testing.T) {
		// Get available templates
		templates := SearchAvailableCertificates(tpm)
		if len(templates) < 2 {
			t.Skip("Need at least 2 EK certificates to test mismatch scenario")
		}

		// Use the certificate from the first template but the public template from another
		// This creates a mismatch between the certificate and the generated public key
		mismatchedTemplate := Template{
			Index:  templates[0].Index,  // Use certificate from first template
			Public: templates[1].Public, // But generate key using second template's spec
		}

		// This should fail during Check() because the generated public key
		// won't match the certificate's public key
		_, err := GetCertificate(tpm, GetCertConfig{
			Template: mismatchedTemplate,
		})

		if err == nil {
			t.Error("GetCertificate() should fail when public key differs from certificate")
		}

		// Verify the error is related to EK check failure
		if !strings.Contains(err.Error(), "untrusted endorsement key") {
			t.Errorf("Expected error to contain 'untrusted endorsement key', got: %v", err)
		}
	})

	t.Run("check Handle is populated properly", func(t *testing.T) {
		ek, err := GetCertificate(tpm, GetCertConfig{
			Template: TemplateECC,
		})
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}

		if ek.Handle != nil {
			t.Error("Expected Handle to be nil (because not persisted yet)")
		}

		_, err = tpmutil.PersistEK(tpm, tpmutil.EKParentConfig{
			KeyFamily:  tpmutil.ECC,
			Handle:     tpmutil.NewHandle(ECCHandle),
			KeyType:    tpmutil.ECCNISTP256,
			IsLowRange: true,
		})
		if err != nil {
			t.Fatalf("PersistEK() failed: %v", err)
		}

		ek2, err := GetCertificate(tpm, GetCertConfig{
			Template: TemplateECC,
		})
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}

		if ek2.Handle == nil {
			t.Error("Expected Handle to be non-nil after persisting EK")
		}
	})
}

func TestSearchCertificates_Integration(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	t.Run("search all certificates with validation", func(t *testing.T) {
		eks, err := SearchCertificates(tpm)
		if err != nil {
			t.Fatalf("SearchCertificates() failed: %v", err)
		}

		if len(eks) == 0 {
			t.Error("SearchCertificates() returned no EKs")
		}

		// Verify each EK has certificate and public key
		for i, ek := range eks {
			if ek.Certificate == nil {
				t.Errorf("EK[%d] has nil certificate", i)
			}
			if ek.Public == nil {
				t.Errorf("EK[%d] has nil public key", i)
			}
			// Verify public key matches certificate
			if ek.Certificate != nil && ek.Public != nil {
				pubKey, err := ek.PublicKey()
				if err != nil {
					t.Errorf("EK[%d] PublicKey() failed: %v", i, err)
				}
				if !equal(ek.Certificate.PublicKey, pubKey) {
					t.Errorf("EK[%d] public key doesn't match certificate", i)
				}
			}
		}
	})

	t.Run("search RSA only", func(t *testing.T) {
		eks, err := SearchCertificates(tpm, SearchCertConfig{
			KeyType: tpm2.TPMAlgRSA,
		})
		if err != nil {
			t.Fatalf("SearchCertificates() failed: %v", err)
		}

		// Should return only RSA EKs
		for i, ek := range eks {
			if ek.Public.Type != tpm2.TPMAlgRSA {
				t.Errorf("EK[%d] has type %v, expected TPMAlgRSA", i, ek.Public.Type)
			}
		}
	})

	t.Run("skip public matching", func(t *testing.T) {
		eks, err := SearchCertificates(tpm, SearchCertConfig{
			SkipPublicMatching: true,
			SkipCheck:          true,
		})
		if err != nil {
			t.Fatalf("SearchCertificates() failed: %v", err)
		}

		if len(eks) == 0 {
			t.Error("SearchCertificates() returned no EKs")
		}

		// EKs should have certificate but no public key
		for i, ek := range eks {
			if ek.Certificate == nil {
				t.Errorf("EK[%d] has nil certificate", i)
			}
			if ek.Public != nil {
				t.Errorf("EK[%d] has public key when SkipPublicMatching is true", i)
			}
		}
	})
}

func TestSearchPersistedTemplates_Integration(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	t.Run("search persisted templates", func(t *testing.T) {
		templates := SearchPersistedTemplates(tpm)

		// Verify templates are valid if any are returned
		for i, tmpl := range templates {
			if tmpl.Index == 0 {
				t.Errorf("Template[%d] has invalid index: 0", i)
			}
			if tmpl.Public.Type == tpm2.TPMAlgNull {
				t.Errorf("Template[%d] has invalid type: TPMAlgNull", i)
			}

			// Verify the template type matches expected algorithm
			algID := tmpl.Type()
			if algID != tpm2.TPMAlgRSA && algID != tpm2.TPMAlgECC {
				t.Errorf("Template[%d] has unexpected algorithm type: %v", i, algID)
			}
		}
	})

	t.Run("persisted templates should be in available templates", func(t *testing.T) {
		persistedTemplates := SearchPersistedTemplates(tpm)
		availableTemplates := SearchAvailableCertificates(tpm)

		if len(availableTemplates) == 0 {
			t.Skip("No available templates on this TPM")
		}

		// Each persisted template should be findable in available templates
		for _, persisted := range persistedTemplates {
			found := false
			for _, available := range availableTemplates {
				if persisted.Index == available.Index && persisted.Public.Type == available.Public.Type {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Persisted template (index=%X, type=%v) not found in available templates",
					persisted.Index, persisted.Public.Type)
			}
		}
	})

	t.Run("persisted templates should have certificates", func(t *testing.T) {
		persistedTemplates := SearchPersistedTemplates(tpm)

		if len(persistedTemplates) == 0 {
			t.Skip("No persisted EK templates on this TPM")
		}

		// Each persisted template should have a corresponding certificate in NVRAM
		for _, template := range persistedTemplates {
			_, err := ReadEKCertFromNVRAM(tpm, template.Index)
			if err != nil {
				t.Errorf("Persisted template (index=%X) has no certificate in NVRAM: %v",
					template.Index, err)
			}
		}
	})

	t.Run("verify persisted handles match known handles", func(t *testing.T) {
		persistedTemplates := SearchPersistedTemplates(tpm)

		// Check if we have RSA or ECC handles
		hasRSA := false
		hasECC := false

		for _, template := range persistedTemplates {
			switch template.Type() {
			case tpm2.TPMAlgRSA:
				hasRSA = true
				// Verify we can read from the RSA handle
				_, err := tpm2.ReadPublic{
					ObjectHandle: RSAHandle,
				}.Execute(tpm)
				if err != nil {
					t.Errorf("Failed to read RSA handle 0x%X: %v", RSAHandle, err)
				}
			case tpm2.TPMAlgECC:
				hasECC = true
				// Verify we can read from the ECC handle
				_, err := tpm2.ReadPublic{
					ObjectHandle: ECCHandle,
				}.Execute(tpm)
				if err != nil {
					t.Errorf("Failed to read ECC handle 0x%X: %v", ECCHandle, err)
				}
			}
		}

		if len(persistedTemplates) > 0 {
			if !hasRSA && !hasECC {
				t.Error("SearchPersistedTemplates returned templates but none are RSA or ECC")
			}
		}
	})
}
