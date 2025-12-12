package endorsement

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
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
