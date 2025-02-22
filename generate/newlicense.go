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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/gravitational/license/authority"
	"github.com/gravitational/license/constants"

	"github.com/gravitational/trace"
)

func newCertificate(licenseParams NewLicenseInfo) ([]byte, error) {
	ca, err := licenseParams.CACertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	signingKey, err := licenseParams.SigningKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	loopbackIP := net.ParseIP(constants.LoopbackIP)
	if loopbackIP == nil {
		return nil, trace.BadParameter("loopback IP is invalid (this is a bug)")
	}

	// Note: starting with Go 1.24, the serial number is generated automatically.
	// Keep this here for now until dependent repos are all on Go 1.24.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, trace.Wrap(err, "generating serial number")
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   constants.LicenseKeyPair,
			Organization: []string{constants.LicenseOrg},
		},
		SerialNumber:          serialNumber,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(licenseParams.ValidFor),
		IPAddresses:           []net.IP{loopbackIP},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    constants.LicenseASN1ExtensionID,
				Value: licenseParams.Payload,
			},
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &licenseParams.PrivateKey.PublicKey, signingKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: constants.CertificatePEMBlock, Bytes: derBytes}); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: constants.RSAPrivateKeyPEMBlock, Bytes: x509.MarshalPKCS1PrivateKey(licenseParams.PrivateKey)}); err != nil {
		return nil, trace.Wrap(err)
	}

	return buf.Bytes(), nil
}

// NewLicenseInfo encapsulates fields needed to generate a license
type NewLicenseInfo struct {
	// ValidFor is validity period for the license
	ValidFor time.Duration
	// PrivateKey is the private key part of the license
	PrivateKey *rsa.PrivateKey
	// TLSKeyPair is the certificate authority to sign the license with
	TLSKeyPair authority.TLSKeyPair
	// Payload is the license payload
	Payload []byte
}

// Check checks the new license request
func (i *NewLicenseInfo) Check() error {
	if time.Now().Add(i.ValidFor).Before(time.Now()) {
		return trace.BadParameter("expiration date can't be in the past")
	}
	if len(i.TLSKeyPair.CertPEM) == 0 {
		return trace.BadParameter("certificate authority must be provided")
	}
	if i.PrivateKey == nil {
		return trace.BadParameter("private key must be provided")
	}

	return nil
}

func (i *NewLicenseInfo) CACertificate() (*x509.Certificate, error) {
	block, _ := pem.Decode(i.TLSKeyPair.CertPEM)
	if block == nil {
		return nil, trace.BadParameter("missing or invalid CA certificate PEM")
	}

	if block.Type != constants.CertificatePEMBlock {
		return nil, trace.BadParameter("invalid PEM block: %v", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, trace.Wrap(err)
}

func (i *NewLicenseInfo) SigningKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(i.TLSKeyPair.KeyPEM)
	if block == nil {
		return nil, trace.BadParameter("missing or invalid CA private key PEM")
	}

	if block.Type != constants.RSAPrivateKeyPEMBlock {
		return nil, trace.BadParameter("invalid PEM block: %v", block.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return privateKey, trace.Wrap(err)
}

// NewLicense generates a new license according to the provided request
func NewLicense(info NewLicenseInfo) (string, error) {
	if err := info.Check(); err != nil {
		return "", trace.Wrap(err)
	}
	certificateBytes, err := newCertificate(info)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return string(certificateBytes), nil
}

// NewPrivateKey generates and returns private key
func NewPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, constants.LicenseKeyBits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return privateKey, nil
}

// AppendAnonymizationKey generates and appends new anonymization key (if one does not already exist)
// to the existing certificate keypair in PEM format.
func AppendAnonymizationKey(licenseContents []byte) ([]byte, error) {
	var anonKey []byte
	blocks := make([]*pem.Block, 0, 3) // cert, private key are expected, anonymization key will be appended
	block, rest := pem.Decode(licenseContents)
	for block != nil {
		switch block.Type {
		case constants.AnonymizationKeyPEMBlock:
			anonKey = block.Bytes
		default:
			blocks = append(blocks, block)
		}
		// parse the next block
		block, rest = pem.Decode(rest)
	}

	if len(anonKey) == 0 {
		anonKey = make([]byte, 16)
		_, err := rand.Read(anonKey)
		if err != nil {
			return nil, trace.Wrap(err, "Error creating anonymization key")
		}
	}

	blocks = append(blocks, []*pem.Block{{
		Type: constants.AnonymizationKeyPEMBlock,
		Headers: map[string]string{ // Headers are just notes for curious users
			"Purpose": "Anonymization of Teleport user activity and resource usage statistics",
			"Caution": "Please ensure that this key is the same in all Teleport instances",
		},
		Bytes: anonKey,
	}}...)

	var result []byte
	for _, block := range blocks {
		result = append(result, pem.EncodeToMemory(block)...)
	}

	return result, nil
}
