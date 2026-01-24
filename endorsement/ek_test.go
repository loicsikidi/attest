package endorsement

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

func readPublicKeyFromPEM(filepath string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

// createTestCert creates a test certificate with proper cryptographic signatures.
func createTestCert(subject, issuer pkix.Name, issuerKey *ecdsa.PrivateKey, issuerCert *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate a new key pair for this certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Determine if this is a CA certificate based on subject/issuer names
	isCA := subject.CommonName != "EK Certificate" && subject.CommonName != "EK Certificate 2"

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                issuer,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	// Only add CertSign for CA certificates
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// If this is a self-signed certificate (root)
	if issuerKey == nil {
		issuerKey = priv
		issuerCert = template
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &priv.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func TestEkCertURL(t *testing.T) {
	type args struct {
		filepath   string
		manufacter string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "RSA intel",
			args: args{
				filepath:   "testdata/intel_rsa_ek.pem",
				manufacter: manufacturerIntel,
			},
			want: "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D",
		},
		{
			name: "ECC intel",
			args: args{
				filepath:   "testdata/intel_ecc_ek.pem",
				manufacter: manufacturerIntel,
			},
			want: "https://ekop.intel.com/ekcertservice/eXT1X6I9wqIMOXll9LoXf0adQelkeaBccmoYU8Kth8o%3D",
		},
		// I didn't found any testing RSA or ECC public key for AMD...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := readPublicKeyFromPEM(tt.args.filepath)
			if err != nil {
				t.Fatalf("readPublicKeyFromPEM() failed: %v", err)
			}

			got := EkCertURL(pub, tt.args.manufacter)
			if got != tt.want {
				t.Errorf("EkCertURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEK_AddChain(t *testing.T) {
	// Create a proper certificate chain with real signatures
	// Root CA (self-signed)
	rootCert, rootKey, err := createTestCert(
		pkix.Name{CommonName: "Root CA"},
		pkix.Name{CommonName: "Root CA"},
		nil, nil, // Self-signed
	)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	// Intermediate CA (signed by Root)
	intermediateCert, intermediateKey, err := createTestCert(
		pkix.Name{CommonName: "Intermediate CA"},
		pkix.Name{CommonName: "Root CA"},
		rootKey, rootCert,
	)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}

	// Another Intermediate CA (signed by Root)
	anotherIntermediateCert, anotherIntermediateKey, err := createTestCert(
		pkix.Name{CommonName: "Another Intermediate CA"},
		pkix.Name{CommonName: "Root CA"},
		rootKey, rootCert,
	)
	if err != nil {
		t.Fatalf("failed to create another intermediate cert: %v", err)
	}

	// EK Certificate (signed by Intermediate)
	ekCert, _, err := createTestCert(
		pkix.Name{CommonName: "EK Certificate"},
		pkix.Name{CommonName: "Intermediate CA"},
		intermediateKey, intermediateCert,
	)
	if err != nil {
		t.Fatalf("failed to create EK cert: %v", err)
	}

	// EK Certificate 2 (signed by Another Intermediate) - for multi-intermediate test
	ekCert2, _, err := createTestCert(
		pkix.Name{CommonName: "EK Certificate 2"},
		pkix.Name{CommonName: "Another Intermediate CA"},
		anotherIntermediateKey, anotherIntermediateCert,
	)
	if err != nil {
		t.Fatalf("failed to create EK cert 2: %v", err)
	}

	tests := []struct {
		name          string
		ekCert        *x509.Certificate
		pool          []*x509.Certificate
		expectedChain int
		expectedCerts []string
		shouldBeNil   bool
	}{
		{
			name:        "Empty pool",
			ekCert:      ekCert,
			pool:        []*x509.Certificate{},
			shouldBeNil: true,
		},
		{
			name:          "Pool with EK cert, intermediate and root",
			ekCert:        ekCert,
			pool:          []*x509.Certificate{ekCert, intermediateCert, rootCert},
			expectedChain: 1,
			expectedCerts: []string{"Intermediate CA"},
		},
		{
			name:          "Pool with only intermediate (no EK cert, no root)",
			ekCert:        ekCert,
			pool:          []*x509.Certificate{intermediateCert},
			expectedChain: 1,
			expectedCerts: []string{"Intermediate CA"},
		},
		{
			name:        "Pool with only root (self-signed)",
			ekCert:      ekCert,
			pool:        []*x509.Certificate{rootCert},
			shouldBeNil: true,
		},
		{
			name:        "Pool with EK cert only",
			ekCert:      ekCert,
			pool:        []*x509.Certificate{ekCert},
			shouldBeNil: true,
		},
		{
			name:        "No EK cert set on EK struct",
			ekCert:      nil,
			pool:        []*x509.Certificate{intermediateCert, rootCert},
			shouldBeNil: true,
		},
		{
			name:          "Complete chain: EK -> Intermediate -> Root",
			ekCert:        ekCert,
			pool:          []*x509.Certificate{ekCert, intermediateCert, rootCert},
			expectedChain: 1,
			expectedCerts: []string{"Intermediate CA"},
		},
		{
			name:          "Two-level chain: EK -> Intermediate (no root in pool)",
			ekCert:        ekCert2,
			pool:          []*x509.Certificate{anotherIntermediateCert, rootCert},
			expectedChain: 1,
			expectedCerts: []string{"Another Intermediate CA"},
		},
		{
			name:          "Pool with multiple intermediates, only one in EK chain",
			ekCert:        ekCert,
			pool:          []*x509.Certificate{ekCert, intermediateCert, anotherIntermediateCert, rootCert},
			expectedChain: 1,
			expectedCerts: []string{"Intermediate CA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ek := &EK{
				Certificate: tt.ekCert,
			}

			ek.AddChain(tt.pool)

			if tt.shouldBeNil {
				if ek.Chain != nil {
					t.Errorf("AddChain() chain should be nil, got %d certificates", len(*ek.Chain))
				}
				return
			}

			if ek.Chain == nil {
				t.Fatalf("AddChain() chain is nil, expected %d certificates", tt.expectedChain)
			}

			if len(*ek.Chain) != tt.expectedChain {
				t.Errorf("AddChain() chain length = %d, want %d", len(*ek.Chain), tt.expectedChain)
			}

			// Verify the certificates in the chain
			for i, expectedCN := range tt.expectedCerts {
				if i >= len(*ek.Chain) {
					t.Errorf("AddChain() missing certificate at index %d", i)
					continue
				}
				cert := (*ek.Chain)[i]
				if cert.Subject.CommonName != expectedCN {
					t.Errorf("AddChain() certificate[%d].Subject.CommonName = %s, want %s",
						i, cert.Subject.CommonName, expectedCN)
				}
			}
		})
	}
}
