package capabilities

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestReadTpmInfo(t *testing.T) {
	simulator, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer simulator.Close()

	if _, err = ReadTpmInfo(simulator); err != nil {
		t.Fatal(err)
	}
}
