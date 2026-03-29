package ek

import _ "embed"

//go:embed testdata/ekcert.pem
var ExpiredEKCert []byte

//go:embed testdata/intel-ekcert.pem
var IntelEKCert []byte
