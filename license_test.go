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

package license

import (
	"testing"
	"time"

	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/cloudflare/cfssl/csr"
	"github.com/pborman/uuid"
	. "gopkg.in/check.v1"
)

func TestLicense(t *testing.T) { TestingT(t) }

type LicenseSuite struct {
	ca authority.TLSKeyPair
}

var _ = Suite(&LicenseSuite{})

func (s *LicenseSuite) SetUpSuite(c *C) {
	// generate certificate authority that will be used in tests
	ca, err := authority.GenerateSelfSignedCA(csr.CertificateRequest{
		CN: constants.LicenseKeyPair,
	})
	c.Assert(err, IsNil)
	s.ca = *ca
}

func (s *LicenseSuite) TestLicense(c *C) {
	dur, err := time.ParseDuration("1h")
	c.Assert(err, IsNil)

	// generate a new license
	license, err := NewLicense(NewLicenseInfo{
		MaxNodes:   3,
		ValidFor:   dur,
		StopApp:    false,
		TLSKeyPair: s.ca,
	})
	c.Assert(err, IsNil)

	// make sure we can parse it
	parsed, err := ParseLicense(license)
	c.Assert(err, IsNil)

	// make sure it verifies successfully
	c.Assert(parsed.Verify(s.ca.CertPEM), IsNil)

	// make sure we can retrieve payload data
	c.Assert(parsed.Payload.MaxNodes, Equals, 3)
}

func (s *LicenseSuite) TestLicenseFromX509(c *C) {
	lic, err := NewLicense(NewLicenseInfo{
		AccountID:  uuid.New(),
		MaxNodes:   3,
		ValidFor:   time.Hour,
		TLSKeyPair: s.ca,
	})
	c.Assert(err, IsNil)

	parsed, err := ParseLicense(lic)
	c.Assert(err, IsNil)

	fromCert, err := ParseLicenseFromX509(parsed.Cert)
	c.Assert(err, IsNil)

	c.Assert(parsed.Payload, DeepEquals, fromCert.Payload)
}
