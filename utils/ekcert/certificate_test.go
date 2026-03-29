package ekcert

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/loicsikidi/attest/internal/utils"
	crlutil "github.com/loicsikidi/attest/internal/utils/crl"
	tpmtest "github.com/loicsikidi/attest/utils/testutil/ek"

	"go.step.sm/crypto/minica"
)

func TestNewEKCertificate(t *testing.T) {
	mockClientHook := func(t *testing.T, ekCert *EKCertificate, revoke bool, delay time.Duration) httpClient {
		t.Helper()
		t.Log("Mocking HTTP client for EK certificate validation")

		localCA, err := minica.New()
		if err != nil {
			t.Fatalf("failed to create local CA: %v", err)
		}

		revokedCerts := []x509.RevocationListEntry{}
		if revoke {
			revokedCerts = append(revokedCerts, x509.RevocationListEntry{
				SerialNumber:   ekCert.GetCertificate().SerialNumber,
				RevocationTime: time.Now().Add(-1 * time.Hour),
			})
		}

		template := &x509.RevocationList{
			Number:                    big.NewInt(1),
			RevokedCertificateEntries: revokedCerts,
			ThisUpdate:                time.Now().Add(-1 * time.Hour),
			NextUpdate:                time.Now().Add(1 * time.Hour),
			SignatureAlgorithm:        x509.ECDSAWithSHA256,
		}

		crlBytes, err := crlutil.MarshalCRL(template, localCA.Intermediate, localCA.Signer)
		if err != nil {
			t.Fatalf("failed to create CRL: %v", err)
		}

		return tpmtest.NewDownloaderWithCRLMockClient(t, delay, crlBytes, localCA.Intermediate.Raw)

	}

	type args struct {
		pemBytes              []byte
		enableRevocationCheck bool
		mustBeRevoked         bool
		delay                 time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "ok wihout revocation check",
			args:    args{pemBytes: tpmtest.IntelEKCert},
			wantErr: false,
		},
		{
			name:    "ok wih revocation check",
			args:    args{pemBytes: tpmtest.IntelEKCert, enableRevocationCheck: true},
			wantErr: false,
		},
		{
			name:    "ko ekcert expired",
			args:    args{pemBytes: tpmtest.ExpiredEKCert},
			wantErr: true,
		},
		{
			name:    "ko ekcert revoked",
			args:    args{pemBytes: tpmtest.IntelEKCert, enableRevocationCheck: true, mustBeRevoked: true},
			wantErr: true,
		},
		{
			name:    "ko AIA chaining failed (timeout)",
			args:    args{pemBytes: tpmtest.IntelEKCert, enableRevocationCheck: true, delay: 2 * tpmtest.DefaultDownloadTimeout},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, err := utils.ParseCertificate(tt.args.pemBytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			ekCert, err := NewEKCertificate(cert, Config{StrictModeEnabled: true})
			if err != nil {
				t.Fatalf("failed to create EKCertificate: %v", err)
			}

			if tt.args.enableRevocationCheck {
				downloader := newDefaultDownloader().(*downloader)
				downloader.SetTimeout(tpmtest.DefaultDownloadTimeout)
				downloader.client = mockClientHook(t, ekCert, tt.args.mustBeRevoked, tt.args.delay)
				ekCert.downloader = downloader
			}

			got := ekCert.Check()
			if tt.wantErr {
				if got == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if got != nil {
					t.Errorf("expected no error, got %v", got)
				}
			}
		})
	}
}
