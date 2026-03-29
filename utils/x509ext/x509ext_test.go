package x509ext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/loicsikidi/attest/utils/oid"
	tpmtest "github.com/loicsikidi/attest/utils/testutil/ek"
	"github.com/loicsikidi/sentinel"
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
			cert, err := parseCertificate(tt.pemBytes)
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

// parseCertificate extracts the first certificate from the given pem.
func parseCertificate(pemData []byte) (*x509.Certificate, error) {
	var block *pem.Block
	for len(pemData) > 0 {
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return nil, sentinel.BadParameter("error decoding pem block")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, sentinel.Wrap(err)
		}
		return cert, nil
	}

	return nil, sentinel.BadParameter("error parsing certificate: no certificate found")
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
