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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer"
	"github.com/gravitational/trace"

	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"
)

func newCertificate(data NewLicenseInfo) ([]byte, error) {
	// make an extension to encode into certificate
	extensions := []signer.Extension{{
		ID:    config.OID(constants.LicenseASN1ExtensionID),
		Value: hex.EncodeToString(data.Payload),
	}}

	req := csr.CertificateRequest{
		CN:    constants.LicenseKeyPair,
		Hosts: []string{constants.LoopbackIP},
		Names: []csr.Name{{
			O: constants.LicenseOrg,
		}},
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  constants.RSAPrivateKeyPEMBlock,
		Bytes: x509.MarshalPKCS1PrivateKey(data.PrivateKey),
	})

	// generate certificate signed by the provided certificate authority
	tlsKeyPair, err := authority.GenerateCertificateWithExtensions(
		req, &data.TLSKeyPair, privatePEM, data.ValidFor, extensions)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resultPEM := append(tlsKeyPair.CertPEM, tlsKeyPair.KeyPEM...)

	if data.CreateAnonymizationKey {
		anonKey := make([]byte, 16)
		_, err := rand.Read(anonKey)
		if err != nil {
			return nil, trace.Wrap(err, "Error creating anonymization key")
		}

		resultPEM = append(resultPEM, pem.EncodeToMemory(&pem.Block{
			Type: constants.AnonymizationKeyPEMBlock,
			Headers: map[string]string{ // Headers are just notes for curious users
				"Purpose": "Anonymization of Teleport user activity and resource usage statistics",
				"Caution": "Please ensure that this key is the same in all Teleport instances",
			},
			Bytes: anonKey,
		})...)
	}

	return resultPEM, nil
}
