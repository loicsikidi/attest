package manufacturer

import (
	"encoding/json"
	"strings"
	"testing"
)

func Test_GetEncodings(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want string
	}{
		{"infineon", 1229346816, "IFX"},
		{"intel", 1229870147, "INTC"},
		{"stm", 1398033696, "STM "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GetEncodings(tt.id); got != tt.want {
				t.Errorf("GetEncodings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetNameByASCII(t *testing.T) {
	tests := []struct {
		name  string
		ascii string
		want  string
	}{
		{"infineon", "IFX", "Infineon"},
		{"intel", "INTC", "Intel"},
		{"stm", "STM ", "ST Microelectronics"},
		{"unknown", "0000", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetNameByASCII(tt.ascii); got != tt.want {
				t.Errorf("GetNameByASCII() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetASCIIFromTPMManufacturerAttr(t *testing.T) {
	tests := []struct {
		name             string
		manufacturerAttr string
		want             string
	}{
		{"nuvoton", "id:4E544300", "NTC"},
		{"intel", "id:494E5443", "INTC"},
		{"invalid format", "000000", ""},
		{"another invalid format", "id:00000:00000", ""},
		{"unknown manufacturer", "id:58585800", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetASCIIFromTPMManufacturerAttr(tt.manufacturerAttr); got != tt.want {
				t.Errorf("GetASCIIFromTPMManufacturerAttr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetTPMManufacturerAttrFromASCII(t *testing.T) {
	tests := []struct {
		name  string
		ascii string
		want  string
	}{
		{"nuvoton", "NTC", "id:4E544300"},
		{"intel", "INTC", "id:494E5443"},
		{"unknown manufacturer", "XXX", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetTPMManufacturerAttrFromASCII(tt.ascii); got != tt.want {
				t.Errorf("GetASCIIFromTPMManufacturerAttr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestID_MarshalJSON(t *testing.T) {
	b, err := json.Marshal(ID(12345678))
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	expected := `"12345678"`
	got := strings.TrimSpace(string(b))
	expectedTrimmed := strings.TrimSpace(expected)
	if got != expectedTrimmed {
		t.Errorf("expected %s, got %s", expectedTrimmed, got)
	}
}

func Test_String(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want string
	}{
		{"infineon", 1229346816, "Infineon"},
		{"unknown", 0, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ID(tt.id).String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
