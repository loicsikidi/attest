package info

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

const blockSize = 1024

// createTestCertificate creates a test certificate for testing purposes.
func createTestCertificate(subject string, isCA bool, keyType string, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	var priv crypto.Signer
	var err error

	if keyType == "ECC" {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if parent == nil {
		parent = &template
		parentKey = priv
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, parent, priv.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// TestGetEKCertChains_Example1 tests GetEKCertChains with Example 1 from TCG TPM v2.0
// Provisioning Guidance section 2.2.1.5.2.
//
// Example 1: TPM with two EK Certificate chains:
// 1. ECC Root CA -> ECC Intermediate CA 1 -> ECC Issuing CA -> ECC EK Certificate (leaf)
// 2. RSA Root CA -> RSA Intermediate CA 1 -> RSA Intermediate CA 2 -> RSA Issuing CA -> RSA EK Certificate (leaf)
func TestGetEKCertChains_MultipleIndices(t *testing.T) {
	// Setup simulated TPM
	tpm := tpmtest.OpenSimulator(t)

	const nvIndexSize = 2048 // Size per NV index as per spec

	// Create ECC chain certificates
	eccRootCA, eccRootKey, err := createTestCertificate("ECC Root CA", true, "ECC", nil, nil)
	if err != nil {
		t.Fatalf("failed to create ECC Root CA: %v", err)
	}

	eccIntermediateCA1, eccIntCA1Key, err := createTestCertificate("ECC Intermediate CA 1", true, "ECC", eccRootCA, eccRootKey)
	if err != nil {
		t.Fatalf("failed to create ECC Intermediate CA 1: %v", err)
	}

	eccIssuingCA, _, err := createTestCertificate("ECC Issuing CA", true, "ECC", eccIntermediateCA1, eccIntCA1Key)
	if err != nil {
		t.Fatalf("failed to create ECC Issuing CA: %v", err)
	}

	// Create RSA chain certificates
	rsaRootCA, rsaRootKey, err := createTestCertificate("RSA Root CA", true, "RSA", nil, nil)
	if err != nil {
		t.Fatalf("failed to create RSA Root CA: %v", err)
	}

	rsaIntermediateCA1, rsaIntCA1Key, err := createTestCertificate("RSA Intermediate CA 1", true, "RSA", rsaRootCA, rsaRootKey)
	if err != nil {
		t.Fatalf("failed to create RSA Intermediate CA 1: %v", err)
	}

	rsaIntermediateCA2, rsaIntCA2Key, err := createTestCertificate("RSA Intermediate CA 2", true, "RSA", rsaIntermediateCA1, rsaIntCA1Key)
	if err != nil {
		t.Fatalf("failed to create RSA Intermediate CA 2: %v", err)
	}

	rsaIssuingCA, _, err := createTestCertificate("RSA Issuing CA", true, "RSA", rsaIntermediateCA2, rsaIntCA2Key)
	if err != nil {
		t.Fatalf("failed to create RSA Issuing CA: %v", err)
	}

	// Build concatenated certificate chain as per Example 1 spec
	// Order: ECC Issuing CA, ECC Intermediate CA 1, RSA Issuing CA, RSA Intermediate CA 2, RSA Intermediate CA 1
	var allCerts bytes.Buffer
	allCerts.Write(eccIssuingCA.Raw)
	allCerts.Write(eccIntermediateCA1.Raw)
	allCerts.Write(rsaIssuingCA.Raw)
	allCerts.Write(rsaIntermediateCA2.Raw)
	allCerts.Write(rsaIntermediateCA1.Raw)

	allCertsData := allCerts.Bytes()

	// Manually distribute certificates across 3 NV indices (2048 bytes each)
	// to simulate overflow behavior as described in Example 1

	// Index 0x01c00100: First 2048 bytes
	index1Data := allCertsData[:min(len(allCertsData), nvIndexSize)]
	if err := tpmutil.NVWrite(tpm, tpmutil.NVWriteConfig{
		Index:      tpm2.TPMHandle(EKCertChainIndexStart),
		Data:       index1Data,
		MultiIndex: false,
	}); err != nil {
		t.Fatalf("failed to write to NV index 0x01c00100: %v", err)
	}

	// Index 0x01c00101: Next 2048 bytes (if available)
	if len(allCertsData) > nvIndexSize {
		index2Start := nvIndexSize
		index2End := min(len(allCertsData), nvIndexSize*2)
		index2Data := allCertsData[index2Start:index2End]
		if err := tpmutil.NVWrite(tpm, tpmutil.NVWriteConfig{
			Index:      tpm2.TPMHandle(EKCertChainIndexStart + 1),
			Data:       index2Data,
			MultiIndex: false,
		}); err != nil {
			t.Fatalf("failed to write to NV index 0x01c00101: %v", err)
		}
	} else {
		t.Error("no data for NV index 0x01c00101")
	}

	// Call GetEKCertChains
	certs, err := GetEKCertChains(tpm, blockSize)
	if err != nil {
		t.Fatalf("GetEKCertChains() failed: %v", err)
	}

	// Verify we got the expected number of certificates (5 total: 2 ECC + 3 RSA, excluding root CAs)
	expectedCount := 5
	if len(certs) != expectedCount {
		t.Errorf("expected %d certificates, got %d", expectedCount, len(certs))
	}

	// Verify certificate subjects in order
	expectedSubjects := []string{
		"ECC Issuing CA",
		"ECC Intermediate CA 1",
		"RSA Issuing CA",
		"RSA Intermediate CA 2",
		"RSA Intermediate CA 1",
	}

	for i, cert := range certs {
		if i >= len(expectedSubjects) {
			break
		}
		if cert.Subject.CommonName != expectedSubjects[i] {
			t.Errorf("certificate[%d]: expected subject %q, got %q", i, expectedSubjects[i], cert.Subject.CommonName)
		}
	}
}

// TestGetEKCertChains_Empty verifies that GetEKCertChains returns an empty slice
// when no EK certificate chains are provisioned in NVRAM.
func TestGetEKCertChains_Empty(t *testing.T) {
	// Setup simulated TPM
	tpm := tpmtest.OpenSimulator(t)

	// Call GetEKCertChains without provisioning any certificates
	certs, err := GetEKCertChains(tpm, blockSize)
	if err != nil {
		t.Fatalf("GetEKCertChains() failed: %v", err)
	}

	if len(certs) != 0 {
		t.Errorf("expected 0 certificates when no EK cert chains provisioned, got %d", len(certs))
	}
}
