package attest

import "github.com/loicsikidi/attest/endorsement"

type SearchEKCertConfig = endorsement.SearchCertConfig
type GetEKCertConfig = endorsement.GetCertConfig
type EKCertTemplate = endorsement.Template

var ErrEKCertNotFound = endorsement.ErrEKCertNotFound
