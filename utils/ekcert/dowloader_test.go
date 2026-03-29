package ekcert

import (
	"context"
	"net/url"
	"testing"

	tpmtest "github.com/loicsikidi/attest/utils/testutil/ek"
	"github.com/nalgeon/be"
)

func Test_DownloadEKCertificate(t *testing.T) {
	t.Parallel()
	client := tpmtest.NewDefaultDowloaderMockClient(t)
	tests := []struct {
		name        string
		ctx         context.Context
		ekURL       string
		wantSubject string
		wantErr     bool
	}{
		{
			name:        "intel",
			ctx:         context.Background(),
			ekURL:       "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D",
			wantSubject: "", // no subject in EK certificate
			wantErr:     false,
		},
		{
			name:        "amd EK CA root",
			ctx:         context.Background(),
			ekURL:       "https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121",            // assumes AMD EK certificate responses are all in the same format
			wantSubject: "CN=AMDTPM,OU=Engineering,O=Advanced Micro Devices,L=Sunnyvale,ST=CA,C=US", // AMDTPM EK CA root subject
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &downloader{client: client, timeout: DefaultDownloadTimeout}
			ekURL, err := url.Parse(tc.ekURL)
			be.Err(t, err, nil)

			got, err := d.DownloadEKCertificate(tc.ctx, ekURL)
			if (err != nil) != tc.wantErr {
				t.Errorf("downloader.DownloadEKCertificate() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if err == nil {
				be.True(t, len(got.Raw) > 0)
				if got.Subject.String() != tc.wantSubject {
					t.Errorf("downloader.downloadEKCertifiate() = %v, want %v", got.Subject.String(), tc.wantSubject)
				}
			}
		})
	}
}
