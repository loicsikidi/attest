package capabilities

import (
	"testing"

	"github.com/loicsikidi/go-tpm-kit/tpmtest"
)

func TestReadTpmInfo(t *testing.T) {
	simulator := tpmtest.OpenSimulator(t)

	if _, err := ReadTpmInfo(simulator); err != nil {
		t.Fatal(err)
	}
}
