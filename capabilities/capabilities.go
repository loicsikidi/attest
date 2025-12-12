package capabilities

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/loicsikidi/attest/algorithm"
	"github.com/loicsikidi/attest/pcr"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMInfo interface {
	Vendor() string
	Manufacturer() uint32
	Revision() string
	FirmwareVersion() string
	FirmwareMajor() int
	FirmwareMinor() int
	IsFIPS140_2() bool
	Algorithms() []algorithm.Algorithm
	NVBufferMaxSize() int
	NVIndexMaxSize() int
	PcrBanks() []pcr.Bank
}

type tpmInfo struct {
	vendor             string
	manufacturer       uint32
	fwMajor            int
	fwMinor            int
	revision           string
	isFIPS140_2        bool
	nvramBufferMaxSize int
	nvramIndexMaxSize  int
	algorithms         []algorithm.Algorithm
	pcrBanks           []pcr.Bank
}

func (t *tpmInfo) Vendor() string {
	return t.vendor
}

func (t *tpmInfo) Manufacturer() uint32 {
	return t.manufacturer
}

func (t *tpmInfo) FirmwareVersion() string {
	return fmt.Sprintf("%d.%d", t.fwMajor, t.fwMinor)
}

func (t *tpmInfo) FirmwareMajor() int {
	return t.fwMajor
}

func (t *tpmInfo) FirmwareMinor() int {
	return t.fwMinor
}

func (t *tpmInfo) IsFIPS140_2() bool {
	return t.isFIPS140_2
}

func (t *tpmInfo) Algorithms() []algorithm.Algorithm {
	return t.algorithms
}

func (t *tpmInfo) Revision() string {
	return t.revision
}

func (t *tpmInfo) NVBufferMaxSize() int {
	return t.nvramBufferMaxSize
}

func (t *tpmInfo) NVIndexMaxSize() int {
	return t.nvramIndexMaxSize
}

func (t *tpmInfo) PcrBanks() []pcr.Bank {
	return t.pcrBanks
}

func ReadTpmInfo(transport transport.TPM) (TPMInfo, error) {
	vendor, err := vendorID(transport)
	if err != nil {
		return nil, err
	}
	manufacturer, err := manufacturer(transport)
	if err != nil {
		return nil, err
	}
	fwMajor, fwMinor, err := firmware(transport)
	if err != nil {
		return nil, err
	}
	fips1402, err := isFIPS140_2(transport)
	if err != nil {
		return nil, err
	}
	revision, err := revision(transport)
	if err != nil {
		return nil, err
	}

	algs, err := algorithms(transport)
	if err != nil {
		return nil, err
	}

	nvramBufferMaxSize, err := nvramBufferMaxSize(transport)
	if err != nil {
		return nil, err
	}

	nvramIndexMaxSize, err := nvIndexMax(transport)
	if err != nil {
		return nil, err
	}

	pcrBanks, err := pcrBanks(transport)
	if err != nil {
		return nil, err
	}

	return &tpmInfo{
		vendor:             vendor,
		manufacturer:       manufacturer,
		fwMajor:            int(fwMajor),
		fwMinor:            int(fwMinor),
		revision:           revision,
		isFIPS140_2:        fips1402,
		algorithms:         algs,
		nvramBufferMaxSize: int(nvramBufferMaxSize),
		nvramIndexMaxSize:  int(nvramIndexMaxSize),
		pcrBanks:           pcrBanks,
	}, nil
}

func vendorID(transport transport.TPM) (string, error) {
	var vendorString string
	props := []tpm2.TPMPT{
		tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4}

	for _, prop := range props {
		vendorRsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}.Execute(transport)
		if err != nil {
			return "", err
		}
		vendorStr, err := vendorRsp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return "", err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, vendorStr.TPMProperty[0].Value)
		vendorString += strings.Trim(string(buf), "\x00")
	}
	return vendorString, nil
}

func manufacturer(transport transport.TPM) (uint32, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return uint32(0), nil
	}
	manufacturer, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return uint32(0), err
	}
	return manufacturer.TPMProperty[0].Value, nil
}

func firmware(transport transport.TPM) (int64, int64, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFirmwareVersion1),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, 0, err
	}
	firmware, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, 0, err
	}
	fw := firmware.TPMProperty[0].Value
	var fwMajor = int64((fw & 0xffff0000) >> 16)
	var fwMinor = int64(fw & 0x0000ffff)
	return fwMajor, fwMinor, nil
}

func isFIPS140_2(transport transport.TPM) (bool, error) {
	modesRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTModes),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return false, err
	}
	modes, err := modesRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return false, err
	}
	return modes.TPMProperty[0].Value == 1, nil
}

func revision(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTRevision),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	revision, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	rev := fmt.Sprintf("%04d", revision.TPMProperty[0].Value)
	major := strings.TrimLeft(rev[:2], "0")
	minor := rev[2:]
	return fmt.Sprintf("%s.%s", major, minor), nil
}

func nvramBufferMaxSize(transport transport.TPM) (uint32, error) {
	modesRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	bufferSize, err := modesRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return bufferSize.TPMProperty[0].Value, nil
}

func nvIndexMax(transport transport.TPM) (uint32, error) {
	modesRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	indexMaxSize, err := modesRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return indexMaxSize.TPMProperty[0].Value, nil
}

func algorithms(transport transport.TPM) ([]algorithm.Algorithm, error) {
	var current tpm2.TPMAlgID = 0x0000 // 0x0000, first property
	caps := []algorithm.Algorithm{}
	for {
		response, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapAlgs,
			Property:      uint32(current),
			PropertyCount: 1,
		}.Execute(transport)
		if err != nil {
			return nil, err
		}
		algs, err := response.CapabilityData.Data.Algorithms()
		if err != nil {
			return nil, err
		}

		if len(algs.AlgProperties) > 0 {
			if !slices.Contains(caps, algorithm.Algorithm(algs.AlgProperties[0].Alg)) {
				caps = append(caps, algorithm.Algorithm(algs.AlgProperties[0].Alg))
			}
		}
		if !response.MoreData {
			break
		}
		current++
	}
	return caps, nil
}

func pcrBanks(transport transport.TPM) ([]pcr.Bank, error) {
	pcrRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return nil, err
	}

	pcrs, err := pcrRsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, fmt.Errorf("failed to read PCR banks: %w", err)
	}
	banks := make([]pcr.Bank, len(pcrs.PCRSelections))
	for i, selection := range pcrs.PCRSelections {
		banks[i] = pcr.Bank{
			Alg:  algorithm.Algorithm(selection.Hash),
			PCRs: tpmutil.PCRSelectToPCRs(selection.PCRSelect),
		}
	}
	return banks, nil
}
