package utils

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/loicsikidi/sentinel"
)

// ParseCertificate extracts the first certificate from the given pem.
func ParseCertificate(pemData []byte) (*x509.Certificate, error) {
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
