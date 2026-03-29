package x509ext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/loicsikidi/attest/internal/utils"
	"github.com/loicsikidi/attest/utils/oid"
	tpmtest "github.com/loicsikidi/attest/utils/testutil/ek"
	"github.com/nalgeon/be"
)

func TestParseEKCert(t *testing.T) {
	type want struct {
		san  *SubjectAltName
		spec *TPMSpecification
	}
	tests := []struct {
		name     string
		pemBytes []byte
		want     want
	}{
		{
			name:     "ok",
			pemBytes: tpmtest.IntelEKCert,
			want: want{
				san: &SubjectAltName{
					TPMManufacturer: "INTC",
					TPMModel:        "SPT",
					TPMVersion:      "id:00020000",
				},
				spec: &TPMSpecification{
					Family:   "2.0",
					Revision: 103,
					Level:    0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO(lsi): migrate to commons/crypto/pemutil
			cert, err := utils.ParseCertificate(tt.pemBytes)
			be.Err(t, err, nil)

			san, err := GetSubjectAltNameFromCertificate(cert)
			be.Err(t, err, nil)
			be.Equal(t, tt.want.san, san)

			spec, err := GetTpmSpecficationFromCertificate(cert)
			be.Err(t, err, nil)
			be.Equal(t, tt.want.spec, spec)

			be.Equal(t, 1, len(cert.UnknownExtKeyUsage))
			be.Equal(t, asn1.ObjectIdentifier(oid.EKCertificate), cert.UnknownExtKeyUsage[0])
		})
	}
}

func TestMarshalTpmSpecification(t *testing.T) {
	tests := []struct {
		name string
		spec *TPMSpecification
	}{
		{
			name: "marshal valid TPMSpecification",
			spec: &TPMSpecification{
				Family:   "2.0",
				Revision: 99,
				Level:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := MarshalTpmSpecification(tt.spec, false)
			be.Err(t, err, nil)

			cert := &x509.Certificate{
				Extensions: []pkix.Extension{ext},
			}

			spec, err := GetTpmSpecficationFromCertificate(cert)
			be.Err(t, err, nil)
			be.Equal(t, tt.spec, spec)
		})
	}
}
