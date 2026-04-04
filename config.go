// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package attest

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// OpenConfig encapsulates settings passed to OpenTPM().
type OpenConfig struct {
	// Transport provides a TPM 2.0 command channel, which can be
	// used in-lieu of any TPM present on the platform.
	Transport transport.TPMCloser
}

// PersistConfig encapsulates parameters for persisting keys.
type PersistConfig struct {
	// Handle is the persistent TPM handle where the key will be stored/loaded.
	//
	// Required.
	Handle tpmutil.Handle

	// CertNVIndex is the NVRAM index where the x509 certificate will be stored/loaded.
	//
	// Required.
	CertNVIndex tpmutil.Handle

	// CertChainNVIndexStart is the starting NV index for the certificate chain.
	//
	// Required.
	CertChainNVIndexStart tpmutil.Handle

	// Parent describes the parent key configuration.
	//
	// Required.
	Parent ParentKeyConfig

	// Certificate is the x509 certificate that certifies this key.
	//
	// Required.
	Certificate *x509.Certificate

	// Chain is the certificate chain that certifies this key.
	//
	// Optional.
	Chain []*x509.Certificate
}

func (c *PersistConfig) CheckAndSetDefaults() error {
	if c.Handle == nil {
		return errors.New("handle is required for persistence")
	}

	if c.Handle.Type() != tpmutil.PersistentHandle {
		return fmt.Errorf("invalid handle type: expected persistent handle, got %v", c.Handle.Type())
	}

	if c.CertNVIndex == nil {
		return errors.New("certificate NVRAM index is required for persistence")
	}

	if c.Certificate == nil {
		return errors.New("certificate is required for persistence")
	}

	if c.Chain != nil && c.CertChainNVIndexStart == nil {
		return errors.New("certificate chain NV index start is required when chain is provided")
	}

	return nil
}

// LoadConfig is an alias for loading operations.
type LoadConfig struct {
	// Handle is the persistent TPM handle where the key will be stored/loaded.
	//
	// Required.
	Handle tpmutil.Handle

	// CertNVIndex is the NVRAM index where the x509 certificate will be stored/loaded.
	//
	// Required.
	CertNVIndex tpmutil.Handle

	// CertChainNVIndexStart is the starting NV index for the certificate chain.
	//
	// Required.
	CertChainNVIndexStart tpmutil.Handle
}

func (c *LoadConfig) CheckAndSetDefaults() error {
	if c.Handle == nil {
		return errors.New("handle is required for loading")
	}

	if c.Handle.Type() != tpmutil.PersistentHandle {
		return fmt.Errorf("invalid handle type: expected persistent handle, got %v", c.Handle.Type())
	}

	if c.CertNVIndex == nil {
		return errors.New("certificate NVRAM index is required for loading")
	}

	return nil
}

// ParentKeyConfig describes the Storage Root Key that is used
type ParentKeyConfig struct {
	SRKAlgorithm algorithm.Algorithm // RSA or ECC/ECDSA
	SRKHandle    tpm2.TPMHandle
	// Handle allows to specify a custom key handle.
	//
	// WARNING: it's the responsibility of the caller
	// to manage the key lifecycle appropriately
	// (i.e., load and close).
	//
	// Notes:
	//   - If not set, the SRKHandle will be used instead.
	//   - Handle only applies to AK keys not Application keys
	//     (at least for now).
	// Default: nil
	Handle tpmutil.Handle
	// Auth is the authorization session for the handle key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
}

func (c *ParentKeyConfig) CheckAndSetDefaults() error {
	if c.Auth == nil {
		c.Auth = tpmutil.NoAuth
	}
	return nil
}

// AKConfig encapsulates parameters for minting keys.
type AKConfig struct {
	// Parent describes the Storage Root Key that will be used as a parent.
	// If nil, the default SRK (i.e. RSA with handle 0x81000001) is assumed.
	// Supported only by TPM 2.0 on Linux.
	//
	// Default: [defaultParentConfig].
	Parent *ParentKeyConfig

	// Key algorithm to be used for the AK.
	//
	// Default: RSA
	Algorithm algorithm.Algorithm
}

func (c *AKConfig) CheckAndSetDefaults() error {
	if c.Parent == nil {
		c.Parent = &defaultParentConfig
	}

	if c.Algorithm == 0 {
		c.Algorithm = algorithm.RSA
	}
	return nil
}

type CertifyConfig struct {
	// Handle is the TPM handle of the key to be certified.
	//
	// Required.
	Handle tpmutil.HandlePublicGetter

	// Auth is the authorization session for the handle key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session

	// QualifyingData is the user provided qualifying data.
	//
	// Optional.
	QualifyingData []byte

	// Certifier is the entity that will certify the key
	// usually an Attestation Key (AK).
	//
	// Note: this field will be populated internally and
	// should not be set by the user.
	certifier certifier
}

func (c *CertifyConfig) CheckAndSetDefaults() error {
	if c.Handle == nil {
		return errors.New("handle is required for certification")
	}

	if c.Auth == nil {
		c.Auth = tpmutil.NoAuth
	}
	return nil
}

// ActivateConfig specifies options for the key certification's challenge generation.
type ActivateConfig struct {
	// EK, the endorsement key, describes an asymmetric key whose
	// private key is permanently bound to the TPM.
	//
	// Activation will verify that the provided EK is held on the same
	// TPM as the key we're certifying. However, it is the caller's responsibility to
	// ensure the EK they provide corresponds to the the device which
	// they are trying to associate the certified key with.
	//
	// Note; LabeledEncapsulationKey interface is a representation of a public key
	EK tpm2.LabeledEncapsulationKey
	// VerifierKeyNameDigest is the name digest of the public key we're using to
	// verify the certification of the tpm-generated key being activated.
	// The verifier key (usually the AK) that owns this digest should be the same
	// key used in VerifyOpts.Public.
	// Use tpm2.ObjectName() to produce the digest for a provided key.
	VerifierKeyNameDigest *tpm2.TPM2BName
}

// VerifyConfig specifies options for the key certification's verification.
//
// The verification relies on two distinct strategies:
//
//   - 1. the remote party know the AK's public key and use it to verify
//     attestation's signature.
//
//   - 2. the remote party has issued a AK certificate as a proof of trust.
//     The attestation is sent along with the certificate for verification.
//     In this case, the remote party MUST ensure the certificate is valid
//     and trusted.
//
//     2A) Public is used to ensure the public key matches the certificate's public key.
//
//     2B) RootPool and IntermediatePool are used to verify the certificate chain.
//
//     Note: 2A has higher priority than 2B.
type VerifyConfig struct {
	// QualifyingData is the challenge qualifying data.
	//
	// Usually a nonce or other unique value to prevent replay attacks
	// and ensure the freshness of the attestation.
	//
	// Optional.
	QualifyingData []byte

	// SkipCertificateExpiryCheck allows skipping the certificate expiry check during verification.
	//
	// Default: false.
	SkipCertificateExpiryCheck bool

	// RootPool is the pool of root certificates used for verification.
	//
	// Default: [x509.SystemCertPool].
	RootPool *x509.CertPool

	// IntermediatePool is the pool of intermediate certificates used for verification.
	//
	// Default: [nil].
	IntermediatePool *x509.CertPool

	// certVerifyOpts is used internally to store the verification options.
	certVerifyOpts *x509.VerifyOptions

	// Public is the public key used to verify key certification.
	//
	// If [CertificationParameters.Certificate] is not nil, then a check
	// will be performed to ensure the public key matches the certificate's
	// public key.
	//
	// Optional if RootPool and/or IntermediatePool is provided.
	Public crypto.PublicKey

	// ValidateFunc is a custom extra validation function for the public key.
	ValidateFunc func(public *tpm2.TPMTPublic) error
}

func (c *VerifyConfig) CheckAndSetDefaults(p CertificationParameters) error {
	if p.Certificate != nil {
		if err := c.setCertVerifyOpts(p.Certificate); err != nil {
			return err
		}
		if err := c.checkCertificate(p.Certificate); err != nil {
			return err
		}

		c.Public = p.Certificate.PublicKey
	}

	return nil
}

func (c *VerifyConfig) setCertVerifyOpts(cert *x509.Certificate) error {
	if c.RootPool == nil {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("failed to load system cert pool: %w", err)
		}
		c.RootPool = systemPool
	}
	c.certVerifyOpts = &x509.VerifyOptions{
		Roots:         c.RootPool,
		Intermediates: c.IntermediatePool,
		// Accept any key usage to support various certificate types
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: func() time.Time {
			if c.SkipCertificateExpiryCheck {
				// Use a time within the certificate's validity period (NotBefore + 1 hour)
				// This works for any certificate regardless of when it was created or expired
				return cert.NotBefore.Add(1 * time.Hour)
			}
			return time.Now()
		}(),
	}
	return nil
}

func (c *VerifyConfig) checkCertificate(cert *x509.Certificate) error {
	// Higher priority: check if the public key matches
	if c.Public != nil {
		pubkey := cert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool })
		if !pubkey.Equal(c.Public) {
			return errors.New("certificate public key does not match provided public key")
		}
		return nil
	}

	// Lower priority: verify the certificate chain
	if _, err := cert.Verify(*c.certVerifyOpts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}
	return nil
}
