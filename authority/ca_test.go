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

type CASuite struct{}

var _ = Suite(&CASuite{})

func (s *CASuite) TestCertLifecycle(c *C) {
	ca, err := GenerateSelfSignedCA(csr.CertificateRequest{
		CN: "cluster.local",
	})
	c.Assert(err, IsNil)
	c.Assert(ca, NotNil)

	keyPair, err := GenerateCertificate(csr.CertificateRequest{
		CN:    "apiserver",
		Hosts: []string{"127.0.0.1"},
		Names: []csr.Name{
			{
				O:  "Gravitational",
				OU: "Local Cluster",
			},
		},
	}, ca, nil, 0)

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
	}, ca, keyPair.KeyPEM, 0)

	c.Assert(err, IsNil)
	c.Assert(keyPair2, NotNil)

	c.Assert(string(keyPair.KeyPEM), DeepEquals, string(keyPair2.KeyPEM))
	c.Assert(string(keyPair.CertPEM), Not(Equals), string(keyPair2.CertPEM))
}
