package pcr

import "crypto"

// PCR encapsulates the value of a PCR at a point in time.
type PCR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash

	// quoteVerified is true if the PCR was verified against a quote
	// in a call to AKPublic.Verify or AKPublic.VerifyAll.
	quoteVerified bool
}

// QuoteVerified returns true if the value of this PCR was previously
// verified against a Quote, in a call to AKPublic.Verify or AKPublic.VerifyAll.
func (p *PCR) QuoteVerified() bool {
	return p.quoteVerified
}

func (p *PCR) SetQuoteVerified(verified bool) {
	p.quoteVerified = verified
}
