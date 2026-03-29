// Package oid contains X.509 and TCG ASN.1 object identifiers.
package oid

import "encoding/asn1"

// Trusted Computing Group (2.23.133)
var (
	// Hardware Type OID assigned to represent TPM 2.0
	TPM20HwType = []int{2, 23, 133, 1, 2}
	// Directory names
	TPMManufacturer  = []int{2, 23, 133, 2, 1}
	TPMModel         = []int{2, 23, 133, 2, 2}
	TPMVersion       = []int{2, 23, 133, 2, 3}
	TPMSpecification = []int{2, 23, 133, 2, 16}
	// Extended Key Usage OIDs
	EKCertificate = []int{2, 23, 133, 8, 1}
	// CertPolicyId OIDs
	VerifiedTPMResidency  = []int{2, 23, 133, 11, 1, 1}
	VerifiedTPMFixed      = []int{2, 23, 133, 11, 1, 2}
	VerifiedTPMRestricted = []int{2, 23, 133, 11, 1, 3}
	IntendedUseDevID      = []int{2, 23, 133, 11, 1, 4}
	// Permanent Identifier Assigner OIDs
	EKPermIDSHA256 = []int{2, 23, 133, 12, 1}
	EKPermIDSHA384 = []int{2, 23, 133, 12, 2}
)

// X.509 (2.23.23)
//
// https://www.itu.int/ITU-T/recommendations/rec.aspx?rec=14033
// https://tools.ietf.org/html/rfc5280
var (
	SubjectDirectoryAttributes = []int{2, 5, 29, 9}
	SubjectAltName             = []int{2, 5, 29, 17}
	CertificatePolicies        = []int{2, 5, 29, 32}
)

// RFC 4043
//
// https://tools.ietf.org/html/rfc4043
var (
	PermanentIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 8, 3}
)

// RFC 4108
//
// https://tools.ietf.org/html/rfc4108
var (
	HardwareModuleName = []int{1, 3, 6, 1, 5, 5, 7, 8, 4}
)

func ToOID(oid []int) asn1.ObjectIdentifier {
	return oid
}
