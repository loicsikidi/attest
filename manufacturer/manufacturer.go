package manufacturer

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	manufacturerByASCII map[string]string
	validChars          *regexp.Regexp
)

// ID represents a unique TCG manufacturer code.
// The canonical reference used is located at:
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
type ID uint32

// MarshalJSON marshals the (numeric) TPM Manufacturer ID to
// a JSON string representation, including quotes.
func (id ID) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(id), 10))
}

// GetEncodings returns the ASCII and hexadecimal representations
// of the manufacturer ID.
func GetEncodings(id ID) (ascii, hexa string) {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], uint32(id))
	ascii = string(b[:])
	ascii = validChars.ReplaceAllString(ascii, "") // NOTE: strips \x00 characters
	hexa = strings.ToUpper(hex.EncodeToString(b[:]))
	return
}

// GetNameByASCII returns the manufacturer name based on its
// ASCII identifier.
func GetNameByASCII(ascii string) string {
	if name, ok := manufacturerByASCII[strings.TrimSpace(ascii)]; ok {
		return name
	}
	return "unknown"
}

// GetASCIIFromTPMManufacturerAttr extracts the ASCII representation
// extracted from 'TPMManufacturer' attribute. The function returns
// an empty string if the input format is invalid or if the ASCII
// is not known by our internal manufacturer list.
//
// This attribute is stored in a EK certificate in the format "id:XXXXXX",
// where "XXXXXX" is the hexadecimal representation of the manufacturer ID (i.e. vendor ID).
//
// Source: TCG EK Credential Profile for TPM Family 2.0 v2.6 [section 3.1.2 TPM Device Attributes]
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf#page=27
func GetASCIIFromTPMManufacturerAttr(tpmManufacturerAttr string) string {
	parts := strings.SplitN(tpmManufacturerAttr, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	hexPart := parts[1]
	b, err := hex.DecodeString(hexPart)
	if err != nil || len(b) != 4 {
		return ""
	}
	ascii := validChars.ReplaceAllString(string(b[:]), "") // NOTE: strips \x00 characters
	if name := GetNameByASCII(ascii); name == "unknown" {
		return ""
	}
	return ascii
}

// GetTPMManufacturerAttrFromASCII returns the 'TPMManufacturer' attribute
// based on the provided ASCII representation. If the ASCII is not known
// by our internal manufacturer list, an empty string is returned.
//
// Source: TCG EK Credential Profile for TPM Family 2.0 v2.6 [section 3.1.2 TPM Device Attributes]
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf#page=27
func GetTPMManufacturerAttrFromASCII(ascii string) string {
	if name := GetNameByASCII(ascii); name == "unknown" {
		return ""
	}
	b := [4]byte{}
	copy(b[:], ascii)
	return "id:" + strings.ToUpper(hex.EncodeToString(b[:]))
}

func init() {
	// manufacturerByASCII contains a mapping of TPM manufacturer
	// ASCII names to full manufacturer names. It is mainly based on the data
	// provided on https://trustedcomputinggroup.org/resource/vendor-id-registry/,
	// e.g. https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
	// Some additional known manufacturers that are not on the list are provided too.
	manufacturerByASCII = map[string]string{
		// 4.1 Product Implementations
		"AMD":  "AMD",
		"ANY":  "Ant Group",
		"ATML": "Atmel",
		"BRCM": "Broadcom",
		"CSCO": "Cisco",
		"FLYS": "Flyslice Technologies",
		"ROCC": "Fuzhou Rockchip",
		"GOOG": "Google",
		"HPI":  "HPI",
		"HPE":  "HPE",
		"HISI": "Huawei",
		"IBM":  "IBM",
		"IFX":  "Infineon",
		"INTC": "Intel",
		"LEN":  "Lenovo",
		"MSFT": "Microsoft",
		"NSM":  "National Semiconductor",
		"NTZ":  "Nationz",
		"NSG":  "NSING",
		"NTC":  "Nuvoton Technology",
		"QCOM": "Qualcomm",
		"SMSN": "Samsung",
		"SECE": "SecEdge",
		"SNS":  "Sinosun",
		"SMSC": "SMSC",
		"STM":  "ST Microelectronics",
		"TXN":  "Texas Instruments",
		"WEC":  "Winbond",
		"SEAL": "WiseKey",

		// 4.2 Simulator and Testing Implementations
		"SIM0": "Simulator 0",
		"SIM1": "Simulator 1",
		"SIM2": "Simulator 2",
		"SIM3": "Simulator 3",
		"SIM4": "Simulator 4",
		"SIM5": "Simulator 5",
		"SIM6": "Simulator 6",
		"SIM7": "Simulator 7",
		"TST0": "Test 0",
		"TST1": "Test 1",
		"TST2": "Test 2",
		"TST3": "Test 3",
		"TST4": "Test 4",
		"TST5": "Test 5",
		"TST6": "Test 6",
		"TST7": "Test 7",
	}

	validChars = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
}

func (id ID) String() string {
	ascii, _ := GetEncodings(id)
	if name, ok := manufacturerByASCII[ascii]; ok {
		return name
	}
	return "unknown"
}
