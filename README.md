## Overview

This directory is a fork of `attest` package from the famous [go-attestation](https://github.com/google/go-attestation) repo from Google.

## Why a fork?

Because I needed to make some changes to the original code to fit my specific use cases. I've made sure to keep the core functionality intact while adding my own enhancements and modifications.

Improvements over the original repo:
 * Migrate from `go-tpm/lecacy/tpm2` to `go-tpm/tpm2` in order to use "TPMDirect" API **ONLY**
 * Add support for ECC attestation keys
  > [!NOTE]
  > ECC support is now available in the original repo as well, but it wasn't the case when I started working on it.
 * Refactor the code to make it more modular (e.g. `algorithm`, `capabilities`, `manufacturer`, etc. sub-packages)
 * Enrich `TPMInfo` struct with more fields (e.g. `Manufacturer`, `Model`, `FirmwareVersion`, etc.)

> [!WARNING]
> **Breaking change**
> - drop support for Windows devices (it could be added back in the future if needed)

Future improvements:
 * Support permission to use TPM's keys (e.g. using passwords or enhanced authorization policies)

## Acknowledgements

This package is a very refactored version of two great packages:
 * [smallstep's crypto tpm sub package](https://github.com/smallstep/crypto/tree/master/tpm)
 * [go-trusted-platform](https://github.com/jeremyhahn/go-trusted-platform)

Make sure to check out the original work!

## Should You Use This?

Probably not. This fork is tailored to my specific needs and may not be suitable for general use. If you're looking for a TPM attestation library, I recommend using the original [go-attestation](https://github.com/google/go-attestation).

--- 

> [!NOTE]
> Find the original README below.

## Example: device identity

TPMs can be used to identify a device remotely and provision unique per-device
hardware-bound keys.

TPMs are provisioned with a set of Endorsement Keys (EKs) by the manufacturer.
These optionally include a certificate signed by the manufacturer and act as a
TPM's identity. For privacy reasons the EK can't be used to sign or encrypt data
directly, and is instead used to attest to the presence of a signing key, an
Attestation Key (AK), on the same TPM. (Newer versions of the spec may allow the
EK to sign directly.)

During attestation, a TPM generates an AK and proves to a certificate authority
that the AK is on the same TPM as a EK. If the certificate authority trusts the
EK, it can transitively trust the AK, for example by issuing a certificate for
the AK.

To perform attestation, the client generates an AK and sends the EK and AK
parameters to the server:

```go
// Client generates an AK and sends it to the server

config := &attest.OpenConfig{}
tpm, err := attest.OpenTPM(config)
if err != nil {
    // handle error
}

eks, err := tpm.EKs()
if err != nil {
    // handle error
}
ek := eks[0]

akConfig := &attest.AKConfig{}
ak, err := tpm.NewAK(akConfig)
if err != nil {
    // handle error
}
attestParams := ak.AttestationParameters()

akBytes, err := ak.Marshal()
if err != nil {
    // handle error
}

if err := os.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {
    // handle error
}

// send TPM version, EK, and attestParams to the server
```

The server uses the EK and AK parameters to generate a challenge encrypted to
the EK, returning the challenge to the client. During this phase, the server
determines if it trusts the EK, either by chaining its certificate to a known
manufacturer and/or querying an inventory system.

```go
// Server validates EK and/or EK certificate

params := attest.NewActivationParameters(ek, attestParams)
secret, encryptedCredentials, err := params.Generate()
if err != nil {
    // handle error
}

// return encrypted credentials to client
```

The client proves possession of the AK by decrypting the challenge and
returning the same secret to the server.

```go
// Client decrypts the credential

akBytes, err := os.ReadFile("encrypted_aik.json")
if err != nil {
    // handle error
}
ak, err := tpm.LoadAK(akBytes)
if err != nil {
    // handle error
}
secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
if err != nil {
    // handle error
}

// return secret to server
```

At this point, the server records the AK and EK association and allows the client
to use its AK as a credential (e.g. by issuing it a client certificate).
