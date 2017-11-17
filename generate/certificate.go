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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/gravitational/license"
	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer"
	"github.com/gravitational/trace"
)

func newCertificate(data NewLicenseInfo) ([]byte, error) {
	private, err := rsa.GenerateKey(rand.Reader, constants.LicenseKeyBits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  constants.RSAPrivateKeyPEMBlock,
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	})

	// encrypt encryption key
	var encryptedKey []byte
	if len(data.EncryptionKey) != 0 {
		encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader,
			private.Public().(*rsa.PublicKey), data.EncryptionKey, nil)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	payload := license.Payload{
		MaxNodes:       data.MaxNodes,
		Expiration:     time.Now().UTC().Add(data.ValidFor),
		Shutdown:       data.StopApp,
		Person:         data.CustomerName,
		Email:          data.CustomerEmail,
		Metadata:       data.CustomerMetadata,
		ProductName:    data.ProductName,
		ProductVersion: data.ProductVersion,
		AccountID:      data.AccountID,
		EncryptionKey:  encryptedKey,
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// make an extension to encode into certificate
	extensions := []signer.Extension{{
		ID:    config.OID(constants.LicenseASN1ExtensionID),
		Value: hex.EncodeToString(bytes),
	}}

	req := csr.CertificateRequest{
		CN:    constants.LicenseKeyPair,
		Hosts: []string{constants.LoopbackIP},
		Names: []csr.Name{{
			O: constants.LicenseOrg,
		}},
	}

	// generate certificate signed by the provided certificate authority
	tlsKeyPair, err := authority.GenerateCertificateWithExtensions(
		req, &data.TLSKeyPair, privatePEM, data.ValidFor, extensions)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return append(tlsKeyPair.CertPEM, tlsKeyPair.KeyPEM...), nil
}
