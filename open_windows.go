//go:build windows

package attest

import "github.com/google/go-tpm/tpm2/transport/windowstpm"

func autoOpenTPM() (*TPM, error) {
	rwc, err := windowstpm.Open()
	if err != nil {
		return nil, err
	}
	base := &tpmbase{rwc: rwc}
	if err := probeTpm(base); err != nil {
		return nil, err
	}
	return &TPM{tpm: base}, nil
}
