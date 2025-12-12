package algorithm

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func Test_AlgorithmString(t *testing.T) {
	tests := []struct {
		name string
		id   tpm2.TPMAlgID
		want string
	}{
		{"ok/RSA", tpm2.TPMAlgRSA, "RSA"},
		{"ok/3DES", 0x0003, "3DES"},
		{"ok/UNKNOWN", math.MaxUint16, "UNKNOWN_ALGORITHM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Algorithm(tt.id).String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_AlgorithmMarshalJSON(t *testing.T) {
	b, err := json.Marshal(Algorithm(tpm2.TPMAlgRSA))
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	expected := `"RSA"`
	got := strings.TrimSpace(string(b))
	expectedTrimmed := strings.TrimSpace(expected)
	if got != expectedTrimmed {
		t.Errorf("expected %s, got %s", expectedTrimmed, got)
	}
}
