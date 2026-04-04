package attest

import "fmt"

type NonceMismatchError struct {
	Expected []byte
	Actual   []byte
}

func (e NonceMismatchError) Error() string {
	return fmt.Sprintf("nonce mismatch: expected %q, got %q", e.Expected, e.Actual)
}
