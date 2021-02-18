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
	"github.com/stretchr/testify/require"
)

type pack struct {
	ca *TLSKeyPair
}

func makePack(t *testing.T) pack {
	ca, err := GenerateSelfSignedCA(csr.CertificateRequest{
		CN: "cluster.local",
	})
	require.NoError(t, err)
	return pack{ca: ca}
}

func TestCertLifecycle(t *testing.T) {
	pack := makePack(t)

	keyPair, err := GenerateCertificate(csr.CertificateRequest{
		CN:    "apiserver",
		Hosts: []string{"127.0.0.1"},
		Names: []csr.Name{
			{
				O:  "Gravitational",
				OU: "Local Cluster",
			},
		},
	}, pack.ca, nil, 0)
	require.NoError(t, err)
	require.NotNil(t, keyPair)

	keyPair2, err := GenerateCertificate(csr.CertificateRequest{
		CN:    "apiserver",
		Hosts: []string{"127.0.0.2"},
		Names: []csr.Name{
			{
				O:  "Gravitational",
				OU: "Local Cluster",
			},
		},
	}, pack.ca, keyPair.KeyPEM, 0)
	require.NoError(t, err)
	require.NotNil(t, keyPair2)

	require.Equal(t, keyPair.KeyPEM, keyPair2.KeyPEM)
	require.NotEqual(t, keyPair.CertPEM, keyPair2.CertPEM)
}
