package attest

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/attest/endorsement"
)

var (
	EKECCHandle = endorsement.ECCHandle
	EKRSAHandle = endorsement.RSAHandle
	SRKHandle   = tpm2.TPMHandle(0x81000001)
)

var ReservedHandles = []tpm2.TPMHandle{
	EKECCHandle,
	EKRSAHandle,
	SRKHandle,
}
