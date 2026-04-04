// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
)

// CertConfig holds configuration for creating a TPM certificate for testing.
type CertConfig struct {
	// Pub is the public key to include in the certificate.
	//
	// Required.
	Pub crypto.PublicKey
	// CA is the certificate authority to sign the certificate.
	// If nil, the certificate will be self-signed.
	//
	// Optional.
	CA *ekca.CA
	// Signer is the private key used to sign the certificate.
	// Only used when CA is nil (for self-signed certificates).
	//
	// Optional (auto-generated if nil and CA is nil).
	Signer crypto.Signer
	// NotBefore is the start time for the certificate validity period.
	//
	// Optional (defaults to 1 hour in the past).
	NotBefore *time.Time
	// NotAfter is the expiration time for the certificate.
	//
	// Optional (defaults to 24 hours from now).
	NotAfter *time.Time
}

// CheckAndSetDefaults validates and sets default values for the certificate configuration.
func (c *CertConfig) CheckAndSetDefaults() error {
	if c.Pub == nil {
		return errors.New("public key is required")
	}

	if c.CA == nil && c.Signer == nil {
		signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		c.Signer = signerKey
	}

	if c.NotBefore == nil {
		notBefore := time.Now().Add(-1 * time.Hour)
		c.NotBefore = &notBefore
	}
	if c.NotAfter == nil {
		notAfter := time.Now().Add(24 * time.Hour)
		c.NotAfter = &notAfter
	}
	return nil
}

// CreateTPMCertificate creates a certificate for a TPM key for testing purposes.
//
// If CA is provided in the config, the certificate is signed by the CA's intermediate certificate.
// Otherwise, the certificate is self-signed using the provided or auto-generated Signer.
func CreateTPMCertificate(t *testing.T, cfg CertConfig) *x509.Certificate {
	t.Helper()

	if err := cfg.CheckAndSetDefaults(); err != nil {
		t.Fatalf("invalid certificate config: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TPM Certificate",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             *cfg.NotBefore,
		NotAfter:              *cfg.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	var certDER []byte
	var err error

	if cfg.CA != nil {
		// Sign with CA's intermediate certificate
		certDER, err = x509.CreateCertificate(rand.Reader, template, cfg.CA.Intermediate, cfg.Pub, cfg.CA.IntSigner)
	} else {
		// Self-signed certificate
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, cfg.Pub, cfg.Signer)
	}

	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
