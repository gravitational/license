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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gravitational/license"
	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/stretchr/testify/require"
)

type pack struct {
	ca         authority.TLSKeyPair
	privateKey *rsa.PrivateKey
}

func makePack(t *testing.T) pack {
	// generate certificate authority that will be used in tests
	ca, err := authority.GenerateSelfSignedCA(constants.LicenseKeyPair, 24*time.Hour*365*5)
	require.NoError(t, err)

	block, _ := pem.Decode(ca.CertPEM)
	require.NotNil(t, block)

	// Make some assertions against the cert to lock in compatibility
	// with older versions of this library.
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, 3, caCert.Version)
	require.Equal(t, x509.SHA256WithRSA, caCert.SignatureAlgorithm)
	require.Equal(t, constants.LicenseKeyPair, caCert.Issuer.CommonName)
	require.Equal(t, constants.LicenseKeyPair, caCert.Subject.CommonName)
	require.WithinDuration(t, time.Now().Add(24*time.Hour*365*5), caCert.NotAfter, 24*time.Hour)
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, caCert.KeyUsage)
	require.Empty(t, caCert.ExtKeyUsage)
	require.True(t, caCert.BasicConstraintsValid)
	require.True(t, caCert.IsCA)

	privateKey, err := rsa.GenerateKey(rand.Reader, constants.LicenseKeyBits)
	require.NoError(t, err)

	return pack{ca: *ca, privateKey: privateKey}
}

func TestNewLicense(t *testing.T) {
	pack := makePack(t)

	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:   time.Hour,
		TLSKeyPair: pack.ca,
		PrivateKey: pack.privateKey,
		Payload:    []byte("foo"),
	})
	require.NoError(t, err)

	t.Run("ParsePEM", func(t *testing.T) {
		parsed, err := license.ParseLicensePEM([]byte(lic))
		require.NoError(t, err)

		require.Equal(t, constants.LicenseKeyPair, parsed.Cert.Subject.CommonName)
		require.Len(t, parsed.Cert.Subject.Organization, 1)
		require.Equal(t, constants.LicenseOrg, parsed.Cert.Subject.Organization[0])
		require.Len(t, parsed.Cert.IPAddresses, 1)
		require.Equal(t, constants.LoopbackIP, parsed.Cert.IPAddresses[0].String())
		require.WithinDuration(t, time.Now().Add(time.Hour), parsed.Cert.NotAfter, 2*time.Minute)

		var teleportExtension pkix.Extension
		for _, ext := range parsed.Cert.Extensions {
			if ext.Id.Equal(constants.LicenseASN1ExtensionID) {
				teleportExtension = ext
				break
			}
		}
		require.NotNil(t, teleportExtension, "license missing cert extension")
		require.Equal(t, "foo", string(teleportExtension.Value))

		require.NoError(t, parsed.Verify(pack.ca.CertPEM))
	})
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
	require.Equal(t, []byte("payload"), parsed.RawPayload)
}

func TestAppendAnonymizationKey(t *testing.T) {
	pack := makePack(t)

	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:   time.Hour,
		TLSKeyPair: pack.ca,
		PrivateKey: pack.privateKey,
		Payload:    []byte("payload"),
	})
	require.NoError(t, err)
	require.NotContains(t, lic, constants.AnonymizationKeyPEMBlock)

	licAppended, err := AppendAnonymizationKey([]byte(lic))
	require.NoError(t, err)
	require.Contains(t, string(licAppended), constants.AnonymizationKeyPEMBlock)

	parsed, err := license.ParseLicensePEM(licAppended)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.AnonymizationKey)

	// Test that appending the anonymization key again does not change the license
	licAppendedAgain, err := AppendAnonymizationKey(licAppended)
	require.NoError(t, err)
	require.Equal(t, string(licAppended), string(licAppendedAgain))
}
