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
	"testing"
	"time"

	"github.com/gravitational/license"
	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/cloudflare/cfssl/csr"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

type pack struct {
	ca         authority.TLSKeyPair
	privateKey *rsa.PrivateKey
}

func makePack(t *testing.T) pack {
	// generate certificate authority that will be used in tests
	ca, err := authority.GenerateSelfSignedCA(csr.CertificateRequest{
		CN: constants.LicenseKeyPair,
	})
	require.NoError(t, err)

	privateKey, err := rsa.GenerateKey(rand.Reader, constants.LicenseKeyBits)
	require.NoError(t, err)

	return pack{ca: *ca, privateKey: privateKey}
}

func TestParseString(t *testing.T) {
	pack := makePack(t)

	dur, err := time.ParseDuration("1h")
	require.NoError(t, err)

	// generate a new license
	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:   dur,
		TLSKeyPair: pack.ca,
		PrivateKey: pack.privateKey,
	})
	require.NoError(t, err)

	// make sure we can parse it
	parsed, err := license.ParseLicensePEM([]byte(lic))
	require.NoError(t, err)

	// make sure it verifies successfully
	require.NoError(t, parsed.Verify(pack.ca.CertPEM))
}

func TestParseX509(t *testing.T) {
	pack := makePack(t)

	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:   time.Hour,
		TLSKeyPair: pack.ca,
		PrivateKey: pack.privateKey,
		Payload:    []byte("payload"),
	})
	require.NoError(t, err)

	parsed, err := license.ParseLicensePEM([]byte(lic))
	require.NoError(t, err)
	require.Empty(t, parsed.AnonymizationKey)

	parsed, err = license.ParseX509(parsed.Cert)
	require.NoError(t, err)
	require.Empty(t, parsed.AnonymizationKey)
}

func TestAnonymizationKey(t *testing.T) {
	pack := makePack(t)

	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:               time.Hour,
		TLSKeyPair:             pack.ca,
		PrivateKey:             pack.privateKey,
		Payload:                []byte("payload"),
		CreateAnonymizationKey: true,
	})
	require.NoError(t, err)

	pemParsed, err := license.ParseLicensePEM([]byte(lic))
	require.NoError(t, err)
	require.NotEmpty(t, pemParsed.AnonymizationKey)

	x509Parsed, err := license.ParseX509(pemParsed.Cert)
	require.NoError(t, err)
	require.NotEmpty(t, x509Parsed.AnonymizationKey)
	require.Equal(t, pemParsed.AnonymizationKey, x509Parsed.AnonymizationKey)
}

func TestSplitPEM(t *testing.T) {
	pack := makePack(t)

	testCases := []struct {
		desc    string
		input   []byte
		err     error
		certPEM []byte
		keyPEM  []byte
	}{
		{
			desc:    "cert + key",
			input:   append(pack.ca.CertPEM, pack.ca.KeyPEM...),
			err:     nil,
			certPEM: pack.ca.CertPEM,
			keyPEM:  pack.ca.KeyPEM,
		},
		{
			desc:    "key + cert",
			input:   append(pack.ca.KeyPEM, pack.ca.CertPEM...),
			err:     nil,
			certPEM: pack.ca.CertPEM,
			keyPEM:  pack.ca.KeyPEM,
		},
		{
			desc:    "only cert",
			input:   pack.ca.CertPEM,
			err:     trace.BadParameter(""),
			certPEM: nil,
			keyPEM:  nil,
		},
		{
			desc:    "only key",
			input:   pack.ca.KeyPEM,
			err:     trace.BadParameter(""),
			certPEM: nil,
			keyPEM:  nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			certPEM, keyPEM, err := license.SplitPEM(tc.input)
			if tc.err != nil {
				require.IsType(t, tc.err, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.certPEM, certPEM)
			require.Equal(t, tc.keyPEM, keyPEM)
		})
	}
}
