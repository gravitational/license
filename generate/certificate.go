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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer"
	"github.com/gravitational/trace"
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

	return append(tlsKeyPair.CertPEM, tlsKeyPair.KeyPEM...), nil
}
