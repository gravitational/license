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

// package authority implements X509 certificate authority features
package authority

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/gravitational/license/constants"

	"github.com/gravitational/trace"
)

// TLSKeyPair is a pair with TLS private key and certificate
type TLSKeyPair struct {
	// KeyPEM is private key PEM encoded contents
	KeyPEM []byte
	// CertPEM is certificate PEM encoded contents
	CertPEM []byte
}

// NewTLSKeyPair returns a new TLSKeyPair with private key and certificate found
// at the provided paths
func NewTLSKeyPair(keyPath, certPath string) (*TLSKeyPair, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &TLSKeyPair{
		KeyPEM:  keyBytes,
		CertPEM: certBytes,
	}, nil
}

// GenerateSelfSignedCA generates a new self signed certificate authority.
// It is intended for testing and local development purposes.
func GenerateSelfSignedCA(commonName string, validFor time.Duration) (*TLSKeyPair, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, constants.TLSKeySize)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, trace.Wrap(err, "generating serial number")
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SerialNumber:          serialNumber,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &keyPair.PublicKey, keyPair)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &TLSKeyPair{
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: constants.RSAPrivateKeyPEMBlock, Bytes: x509.MarshalPKCS1PrivateKey(keyPair)}),
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: constants.CertificatePEMBlock, Bytes: derBytes}),
	}, nil
}
