package quote

import (
	"github.com/google/go-tpm/tpm2"
)

// Quote encapsulates the results of a Quote operation against the TPM,
// using an attestation key.
type Quote struct {
	Quote     tpm2.TPMSAttest
	Signature tpm2.TPMTSignature
}

type quote struct {
	Quote     []byte
	Signature []byte
}

func (q Quote) ToRaw() quote {
	return quote{
		Quote:     tpm2.Marshal(q.Quote),
		Signature: tpm2.Marshal(q.Signature),
	}
}

// QuoteFromRaw converts a raw quote to a Quote structure.
func QuoteFromRaw(q quote) (*Quote, error) {
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](q.Signature)
	if err != nil {
		return nil, err
	}
	quote, err := tpm2.Unmarshal[tpm2.TPMSAttest](q.Quote)
	if err != nil {
		return nil, err
	}
	return &Quote{
		Quote:     *quote,
		Signature: *sig,
	}, nil
}
