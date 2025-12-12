package pcr

import (
	"fmt"
	"strings"

	"github.com/loicsikidi/attest/algorithm"

	"github.com/loicsikidi/attest/internal/utils/slices"
)

type Bank struct {
	// PCR bank algorithm.
	// Possible values are SHA1, SHA256, SHA384 and SHA512.
	Alg  algorithm.Algorithm `json:"alg"`
	PCRs []uint              `json:"pcrs"`
}

// String returns a textual representation of the PCR bank.
// Please find below an example:
//
//	SHA-256: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
func (b Bank) String() string {
	pcrsStrings := slices.UintToString(b.PCRs)
	return fmt.Sprintf("%s: [%s]", b.Alg.String(), strings.Join(pcrsStrings, ", "))
}

// IsAvailable checks if the PCR bank has any PCRs defined.
func (b Bank) IsAvailable() bool {
	return len(b.PCRs) > 0
}
