// Package x509ext provides functions for (un)marshalling X.509 extensions not
// supported by the crypto/x509 package.
package x509ext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/loicsikidi/attest/manufacturer"
	"github.com/loicsikidi/attest/utils/oid"
	"github.com/loicsikidi/sentinel"
)

// OtherName represents an ASN.1 encoded "other name" as
// defined by RFC5280.
//
//	OtherName ::= SEQUENCE {
//		  type-id    OBJECT IDENTIFIER,
//		  value      [0] EXPLICIT ANY DEFINED BY type-id
//	}
//
// OtherName is one type of Subject Alternative Name (SAN)
//
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

func marshalOtherName(typeID asn1.ObjectIdentifier, value any) (asn1.RawValue, error) {
	valueBytes, err := asn1.MarshalWithParams(value, "explicit,tag:0")
	if err != nil {
		return asn1.RawValue{}, sentinel.Wrap(err)
	}
	otherName := otherName{
		TypeID: typeID,
		Value:  asn1.RawValue{FullBytes: valueBytes},
	}
	bytes, err := asn1.MarshalWithParams(otherName, "tag:0")
	if err != nil {
		return asn1.RawValue{}, sentinel.Wrap(err)
	}
	return asn1.RawValue{FullBytes: bytes}, nil
}

// HardwareModuleName represents an ASN.1 encoded "hardware module name" as
// defined by RFC4108.
//
//	HardwareModuleName ::= SEQUENCE {
//	   hwType OBJECT IDENTIFIER
//	   hwSerialNum OCTET STRING
//	}
//
// https://datatracker.ietf.org/doc/html/rfc4108
type HardwareModuleName struct {
	HwType      asn1.ObjectIdentifier
	HwSerialNum []byte `asn1:"tag:4"`
}

func parseHardwareModuleName(der []byte) (HardwareModuleName, error) {
	var hwModuleName HardwareModuleName
	if _, err := asn1.UnmarshalWithParams(der, &hwModuleName, "explicit,tag:0"); err != nil {
		return HardwareModuleName{}, sentinel.Wrap(err)
	}
	return hwModuleName, nil
}

// PermanentIdentifier represents an ASN.1 encoded "permanent identifier" as
// defined by RFC4043.
//
//	PermanentIdentifier ::= SEQUENCE {
//		    identifierValue    UTF8String OPTIONAL,
//		    assigner           OBJECT IDENTIFIER OPTIONAL
//	}
//
// https://datatracker.ietf.org/doc/html/rfc4043
type PermanentIdentifier struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

func parsePermanentIdentifier(der []byte) (PermanentIdentifier, error) {
	var permID PermanentIdentifier
	if _, err := asn1.UnmarshalWithParams(der, &permID, "explicit,tag:0"); err != nil {
		return PermanentIdentifier{}, err
	}
	return permID, nil
}

// TPMManufacturer is an ASCII representation of the hexadecimal
// value of the 4-byte vendor ID prefixed by "id:" (e.g. "id:414D4400" for AMD).
//
// This representation is not very user friendly, so we provide
// the value as an ASCII string (e.g. "AMD").
//
// Use
//   - String() to get the ASCII representation
//   - Raw() to get the original hexadecimal representation.
type tpmmanufacturer string

func newTPMManufacturer(s string) tpmmanufacturer {
	ascii := manufacturer.GetASCIIFromTPMManufacturerAttr(s)
	return tpmmanufacturer(ascii)
}

func (t tpmmanufacturer) String() string {
	return string(t)
}

func (t tpmmanufacturer) Raw() string {
	return manufacturer.GetTPMManufacturerAttrFromASCII(string(t))
}

// SubjectAltName contains GeneralName variations not supported by the
// crypto/x509 package.
//
// https://datatracker.ietf.org/doc/html/rfc5280
type SubjectAltName struct {
	TPMManufacturer      tpmmanufacturer
	TPMModel             string
	TPMVersion           string
	PermanentIdentifiers []PermanentIdentifier
	HardwareModuleNames  []HardwareModuleName
}

// ParseSubjectAltName parses a pkix.Extension into a SubjectAltName struct.
func ParseSubjectAltName(ext pkix.Extension) (*SubjectAltName, error) {
	var out SubjectAltName
	dirNames, otherNames, err := parseSubjectAltName(ext)
	if err != nil {
		return nil, sentinel.Wrap(err)
	}

	for _, dirName := range dirNames {
		for _, attr := range dirName.Names {
			switch {
			case attr.Type.Equal(oid.TPMManufacturer):
				out.TPMManufacturer = newTPMManufacturer(attr.Value.(string))
			case attr.Type.Equal(oid.TPMModel):
				out.TPMModel = attr.Value.(string)
			case attr.Type.Equal(oid.TPMVersion):
				out.TPMVersion = attr.Value.(string)
			}
		}
	}

	for _, otherName := range otherNames {
		switch {
		case otherName.TypeID.Equal(oid.PermanentIdentifier):
			permID, err := parsePermanentIdentifier(otherName.Value.FullBytes)
			if err != nil {
				return nil, sentinel.Wrap(err)
			}
			out.PermanentIdentifiers = append(out.PermanentIdentifiers, permID)
		case otherName.TypeID.Equal(oid.HardwareModuleName):
			hwModuleName, err := parseHardwareModuleName(otherName.Value.FullBytes)
			if err != nil {
				return nil, sentinel.Wrap(err)
			}
			out.HardwareModuleNames = append(out.HardwareModuleNames, hwModuleName)
		default:
			return nil, sentinel.BadParameter("expected type id %v, got %v", oid.PermanentIdentifier, otherName.TypeID)
		}
	}
	return &out, nil
}

// GetSubjectAltNameFromCertificate parses x509.Certificate.Extensions
// in order to produce a SubjectAltName struct.
func GetSubjectAltNameFromCertificate(cert *x509.Certificate) (*SubjectAltName, error) {
	var out SubjectAltName
	if cert != nil {
		ext, err := GetSubjectAltNameExtensionFromCertificate(cert)
		if err != nil {
			return nil, sentinel.Wrap(err)
		}
		return ParseSubjectAltName(ext)
	}
	return &out, nil
}

// GetSubjectAltNameFromCertificate parses x509.Certificate.Extensions
// in order to produce a SubjectAltName struct.
func GetSubjectAltNameExtensionFromCertificate(cert *x509.Certificate) (pkix.Extension, error) {
	if cert != nil {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid.SubjectAltName) {
				return ext, nil
			}
		}
	}
	return pkix.Extension{}, sentinel.NotFound("subject alt name extension not found")
}

// https://datatracker.ietf.org/doc/html/rfc5280#page-35
func parseSubjectAltName(ext pkix.Extension) (dirNames []pkix.Name, otherNames []otherName, err error) {
	err = forEachSAN(ext.Value, func(generalName asn1.RawValue) error {
		switch generalName.Tag {
		case 0: // otherName
			var otherName otherName
			if _, err := asn1.UnmarshalWithParams(generalName.FullBytes, &otherName, "tag:0"); err != nil {
				return sentinel.Wrap(err, "failed to asn1 unmarshal OtherName field")
			}
			otherNames = append(otherNames, otherName)
		case 4: // directoryName
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(generalName.Bytes, &rdns); err != nil {
				return sentinel.Wrap(err, "failed to asn1 unmarshal DirectoryName field")
			}
			var dirName pkix.Name
			dirName.FillFromRDNSequence(&rdns)
			dirNames = append(dirNames, dirName)
		default:
			return sentinel.BadParameter("expected tag %d", generalName.Tag)
		}
		return nil
	})
	return
}

// Borrowed from the x509 package.
func forEachSAN(extension []byte, callback func(ext asn1.RawValue) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return sentinel.Wrap(err)
	}
	if len(rest) != 0 {
		return sentinel.BadParameter("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return sentinel.Wrap(asn1.StructuralError{Msg: "bad SAN sequence"})
	}

	rest = seq.Bytes
	for len(rest) > 0 {

		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return sentinel.Wrap(err)
		}

		if err := callback(v); err != nil {
			return sentinel.Wrap(err)
		}
	}

	return nil
}

func marshalSANToRDNSequence(san *SubjectAltName) (asn1.RawValue, error) {
	var rdns pkix.RDNSequence
	if san.TPMManufacturer != "" {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{
			Type:  oid.TPMManufacturer,
			Value: san.TPMManufacturer.Raw(),
		}})
	}
	if san.TPMModel != "" {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{
			Type:  oid.TPMModel,
			Value: san.TPMModel,
		}})
	}
	if san.TPMVersion != "" {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{
			Type:  oid.TPMVersion,
			Value: san.TPMVersion,
		}})
	}

	dirNameBytes, err := asn1.MarshalWithParams(rdns, "explicit,tag:4")
	if err != nil {
		return asn1.RawValue{}, sentinel.Wrap(err)
	}
	return asn1.RawValue{FullBytes: dirNameBytes}, nil
}

// MarshalSubjectAltName converts a SubjectAltName struct into a pkix.Extension,
// allowing callers to specify if the extension is critical.
func MarshalSubjectAltName(san *SubjectAltName, critical bool) (pkix.Extension, error) {
	if san == nil {
		return pkix.Extension{}, sentinel.BadParameter("san cannot be nil")
	}

	var generalNames []asn1.RawValue

	// Convert TPM attributes back to dirName format
	dirName, err := marshalSANToRDNSequence(san)
	if err != nil {
		return pkix.Extension{}, sentinel.Wrap(err)
	}
	generalNames = append(generalNames, dirName)

	for _, permID := range san.PermanentIdentifiers {
		val, err := marshalOtherName(oid.PermanentIdentifier, permID)
		if err != nil {
			return pkix.Extension{}, sentinel.Wrap(err)
		}
		generalNames = append(generalNames, val)
	}
	for _, hwModuleName := range san.HardwareModuleNames {
		val, err := marshalOtherName(oid.HardwareModuleName, hwModuleName)
		if err != nil {
			return pkix.Extension{}, sentinel.Wrap(err)
		}
		generalNames = append(generalNames, val)
	}
	val, err := asn1.Marshal(generalNames)
	if err != nil {
		return pkix.Extension{}, sentinel.Wrap(err)
	}
	return pkix.Extension{
		Id:       oid.SubjectAltName,
		Critical: critical,
		Value:    val,
	}, nil
}

// TPMSpecification represents the TPM specification as defined by TCG.
//
//	TPMSpecification ::= SEQUENCE {
//			family UTF8String (SIZE (1..STRMAX)),
//			level INTEGER,
//			revision INTEGER
//	}
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf#page=26
type TPMSpecification struct {
	Family   string `asn1:"utf8"`
	Level    int
	Revision int
}

// GetTpmSpecficationFromCertificate parses x509.Certificate.Extensions
// in order to produce a TPMSpecification struct.
func GetTpmSpecficationFromCertificate(cert *x509.Certificate) (*TPMSpecification, error) {
	out := new(TPMSpecification)
	if cert != nil {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid.SubjectDirectoryAttributes) {
				var seq asn1.RawValue
				rest, err := asn1.Unmarshal(ext.Value, &seq)
				if err != nil {
					return out, sentinel.Wrap(err)
				}
				if len(rest) != 0 {
					return out, sentinel.BadParameter("trailing data after X.509 extension")
				}
				rest = seq.Bytes
				for len(rest) > 0 {
					var e struct {
						ID   asn1.ObjectIdentifier
						Data asn1.RawValue
					}
					rest, err = asn1.Unmarshal(rest, &e)
					if err != nil {
						return out, sentinel.Wrap(err)
					}
					switch {
					case e.ID.Equal(oid.TPMSpecification):
						if _, err := asn1.Unmarshal(e.Data.Bytes, out); err != nil {
							return nil, err
						}
					default:
						return out, sentinel.BadParameter("unhandled TCG directory attribute: %v", e.ID)
					}
				}
			}
		}
	}
	return out, nil
}

// MarshalTpmSpecification converts a TPMSpecification struct into a pkix.Extension
// containing the Subject Directory Attributes extension with TPM specification.
func MarshalTpmSpecification(spec *TPMSpecification, critical bool) (pkix.Extension, error) {
	if spec == nil {
		return pkix.Extension{}, sentinel.BadParameter("spec cannot be nil")
	}

	specBytes, err := asn1.MarshalWithParams(*spec, "explicit,tag:0")
	if err != nil {
		return pkix.Extension{}, sentinel.Wrap(err)
	}

	attr := struct {
		ID   asn1.ObjectIdentifier
		Data asn1.RawValue `asn1:"set"`
	}{
		ID:   oid.TPMSpecification,
		Data: asn1.RawValue{FullBytes: specBytes},
	}

	attrs := []any{attr}
	extBytes, err := asn1.Marshal(attrs)
	if err != nil {
		return pkix.Extension{}, sentinel.Wrap(err)
	}

	return pkix.Extension{
		Id:       oid.SubjectDirectoryAttributes,
		Critical: critical,
		Value:    extBytes,
	}, nil
}

// MarshalCertificatePolicies converts a slice of OID into a pkix.Extension,
// allowing callers to specify if the extension is critical.
func MarshalCertificatePolicies(policyOIDs []asn1.ObjectIdentifier, critical bool) (pkix.Extension, error) {
	// Structure ASN.1 pour Certificate Policies
	type policyInformation struct {
		PolicyIdentifier asn1.ObjectIdentifier
	}

	var policies []policyInformation
	for _, oid := range policyOIDs {
		policies = append(policies, policyInformation{
			PolicyIdentifier: oid,
		})
	}

	policyBytes, err := asn1.Marshal(policies)
	if err != nil {
		return pkix.Extension{}, sentinel.Wrap(err)
	}

	return pkix.Extension{
		Id:       oid.CertificatePolicies,
		Critical: critical,
		Value:    policyBytes,
	}, nil
}
