// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This has been renamed from tpm_linux.go to open.go and modified by lsikidi.
package attest

import (
	"os"
	"path"
	"strings"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func probeSystemTPMs() ([]string, error) {
	var tpms []string

	tpmDevs, err := os.ReadDir(tpmRoot)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		for _, tpmDev := range tpmDevs {
			if strings.HasPrefix(tpmDev.Name(), "tpm") {
				tpmPath := path.Join(tpmRoot, tpmDev.Name())

				if _, err := os.Stat(path.Join(tpmPath, "caps")); err == nil {
					continue
				} else if !os.IsNotExist(err) {
					return nil, err
				}
				tpms = append(tpms, tpmPath)
			}
		}
	}

	return tpms, nil
}

func openTPM(tpmPath string) (*TPM, error) {
	// If the TPM has a kernel-provided resource manager, we should
	// use that instead of communicating directly.
	devPath := path.Join("/dev", path.Base(tpmPath))
	f, err := os.ReadDir(path.Join(tpmPath, "device", "tpmrm"))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else if len(f) > 0 {
		devPath = path.Join("/dev", f[0].Name())
	}

	rwc, err := linuxtpm.Open(devPath)
	if err != nil {
		return nil, err
	}

	return &TPM{tpm: &tpmbase{
		rwc: rwc,
	}}, nil
}
