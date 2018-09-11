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
	. "gopkg.in/check.v1"
)

func TestParse(t *testing.T) { TestingT(t) }

type ParseSuite struct {
	ca         authority.TLSKeyPair
	privateKey *rsa.PrivateKey
}

var _ = Suite(&ParseSuite{})

func (s *ParseSuite) SetUpSuite(c *C) {
	// generate certificate authority that will be used in tests
	ca, err := authority.GenerateSelfSignedCA(csr.CertificateRequest{
		CN: constants.LicenseKeyPair,
	})
	c.Assert(err, IsNil)

	privateKey, err := rsa.GenerateKey(rand.Reader, constants.LicenseKeyBits)
	c.Assert(err, IsNil)

	s.ca = *ca
	s.privateKey = privateKey
}

func (s *ParseSuite) TestParseString(c *C) {
	dur, err := time.ParseDuration("1h")
	c.Assert(err, IsNil)

	// generate a new license
	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:   dur,
		TLSKeyPair: s.ca,
		PrivateKey: s.privateKey,
	})
	c.Assert(err, IsNil)

	// make sure we can parse it
	parsed, err := license.ParseLicensePEM([]byte(lic))
	c.Assert(err, IsNil)

	// make sure it verifies successfully
	c.Assert(parsed.Verify(s.ca.CertPEM), IsNil)
}

func (s *ParseSuite) TestParseX509(c *C) {
	lic, err := NewLicense(NewLicenseInfo{
		ValidFor:   time.Hour,
		TLSKeyPair: s.ca,
		PrivateKey: s.privateKey,
	})
	c.Assert(err, IsNil)

	parsed, err := license.ParseLicensePEM([]byte(lic))
	c.Assert(err, IsNil)

	_, err = license.ParseX509(parsed.Cert)
	c.Assert(err, IsNil)
}

func (s *ParseSuite) TestSplitPEM(c *C) {
	testCases := []struct {
		desc    string
		input   []byte
		err     error
		certPEM []byte
		keyPEM  []byte
	}{
		{
			desc:    "cert + key",
			input:   append(s.ca.CertPEM, s.ca.KeyPEM...),
			err:     nil,
			certPEM: s.ca.CertPEM,
			keyPEM:  s.ca.KeyPEM,
		},
		{
			desc:    "key + cert",
			input:   append(s.ca.KeyPEM, s.ca.CertPEM...),
			err:     nil,
			certPEM: s.ca.CertPEM,
			keyPEM:  s.ca.KeyPEM,
		},
		{
			desc:    "only cert",
			input:   s.ca.CertPEM,
			err:     trace.BadParameter(""),
			certPEM: nil,
			keyPEM:  nil,
		},
		{
			desc:    "only key",
			input:   s.ca.KeyPEM,
			err:     trace.BadParameter(""),
			certPEM: nil,
			keyPEM:  nil,
		},
	}
	for _, tc := range testCases {
		certPEM, keyPEM, err := license.SplitPEM(tc.input)
		if tc.err != nil {
			c.Assert(err, FitsTypeOf, tc.err, Commentf(tc.desc))
		} else {
			c.Assert(err, IsNil, Commentf(tc.desc))
		}
		c.Assert(certPEM, DeepEquals, tc.certPEM, Commentf(tc.desc))
		c.Assert(keyPEM, DeepEquals, tc.keyPEM, Commentf(tc.desc))
	}
}
