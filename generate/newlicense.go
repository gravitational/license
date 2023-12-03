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
	// CreateAnonymizationKey specifies whether a key should be created
	// for this license to anonymize usage data
	CreateAnonymizationKey bool
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
