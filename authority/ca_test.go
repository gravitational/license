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

package authority

import (
	"testing"

	"github.com/cloudflare/cfssl/csr"
	. "gopkg.in/check.v1"
)

func TestCA(t *testing.T) { TestingT(t) }

type CASuite struct {
	ca *TLSKeyPair
}

var _ = Suite(&CASuite{})

func (s *CASuite) SetUpSuite(c *C) {
	ca, err := GenerateSelfSignedCA(csr.CertificateRequest{
		CN: "cluster.local",
	})
	c.Assert(err, IsNil)
	s.ca = ca
}

func (s *CASuite) TestCertLifecycle(c *C) {
	keyPair, err := GenerateCertificate(csr.CertificateRequest{
		CN:    "apiserver",
		Hosts: []string{"127.0.0.1"},
		Names: []csr.Name{
			{
				O:  "Gravitational",
				OU: "Local Cluster",
			},
		},
	}, s.ca, nil, 0)

	c.Assert(err, IsNil)
	c.Assert(keyPair, NotNil)

	keyPair2, err := GenerateCertificate(csr.CertificateRequest{
		CN:    "apiserver",
		Hosts: []string{"127.0.0.2"},
		Names: []csr.Name{
			{
				O:  "Gravitational",
				OU: "Local Cluster",
			},
		},
	}, s.ca, keyPair.KeyPEM, 0)

	c.Assert(err, IsNil)
	c.Assert(keyPair2, NotNil)

	c.Assert(string(keyPair.KeyPEM), DeepEquals, string(keyPair2.KeyPEM))
	c.Assert(string(keyPair.CertPEM), Not(Equals), string(keyPair2.CertPEM))
}

func (s *CASuite) TestSplitPEM(c *C) {
	// cert + key
	combinedPEM := append(s.ca.CertPEM, s.ca.KeyPEM...)
	certPEM, keyPEM, err := SplitPEM(combinedPEM)
	c.Assert(err, IsNil)
	c.Assert(certPEM, DeepEquals, s.ca.CertPEM)
	c.Assert(keyPEM, DeepEquals, s.ca.KeyPEM)

	// key + cert
	combinedPEM = append(s.ca.KeyPEM, s.ca.CertPEM...)
	certPEM, keyPEM, err = SplitPEM(combinedPEM)
	c.Assert(err, IsNil)
	c.Assert(certPEM, DeepEquals, s.ca.CertPEM)
	c.Assert(keyPEM, DeepEquals, s.ca.KeyPEM)

	// cert only
	_, _, err = SplitPEM(s.ca.CertPEM)
	c.Assert(err, NotNil)

	// key only
	_, _, err = SplitPEM(s.ca.KeyPEM)
	c.Assert(err, NotNil)
}
