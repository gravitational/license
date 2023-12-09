/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package generate

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"time"

	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/gravitational/trace"
)

// NewLicenseInfo encapsulates fields needed to generate a license
type NewLicenseInfo struct {
	// ValidFor is validity period for the license
	ValidFor time.Duration
	// PrivateKey is the private key part of the license
	PrivateKey *rsa.PrivateKey
	// TLSKeyPair is the certificate authority to sign the license with
	TLSKeyPair authority.TLSKeyPair
	// Payload is the license payload
	Payload []byte
}

// Check checks the new license request
func (i *NewLicenseInfo) Check() error {
	if time.Now().Add(i.ValidFor).Before(time.Now()) {
		return trace.BadParameter("expiration date can't be in the past")
	}
	if len(i.TLSKeyPair.CertPEM) == 0 {
		return trace.BadParameter("certificate authority must be provided")
	}
	if i.PrivateKey == nil {
		return trace.BadParameter("private key must be provided")
	}

	return nil
}

// NewLicense generates a new license according to the provided request
func NewLicense(info NewLicenseInfo) (string, error) {
	if err := info.Check(); err != nil {
		return "", trace.Wrap(err)
	}
	certificateBytes, err := newCertificate(info)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return string(certificateBytes), nil
}

// NewPrivateKey generates and returns private key
func NewPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, constants.LicenseKeyBits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return privateKey, nil
}

// AppendAnonymizationKey generates and appends new anonymization key (if one does not already exist)
// to the existing certificate keypair in PEM format.
func AppendAnonymizationKey(licenseContents []byte) ([]byte, error) {
	var anonKey []byte
	blocks := make([]*pem.Block, 0, 3) // cert, private key are expected, anonymization key will be appended
	block, rest := pem.Decode(licenseContents)
	for block != nil {
		switch block.Type {
		case constants.AnonymizationKeyPEMBlock:
			anonKey = block.Bytes
		default:
			blocks = append(blocks, block)
		}
		// parse the next block
		block, rest = pem.Decode(rest)
	}

	if len(anonKey) == 0 {
		anonKey = make([]byte, 16)
		_, err := rand.Read(anonKey)
		if err != nil {
			return nil, trace.Wrap(err, "Error creating anonymization key")
		}
	}

	blocks = append(blocks, []*pem.Block{{
		Type: constants.AnonymizationKeyPEMBlock,
		Headers: map[string]string{ // Headers are just notes for curious users
			"Purpose": "Anonymization of Teleport user activity and resource usage statistics",
			"Caution": "Please ensure that this key is the same in all Teleport instances",
		},
		Bytes: anonKey,
	}}...)

	var result []byte
	for _, block := range blocks {
		result = append(result, pem.EncodeToMemory(block)...)
	}

	return result, nil
}
