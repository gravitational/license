/*
Copyright 2025 Gravitational, Inc.

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

package parse

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/gravitational/trace"
)

const (
	pkcs1PrivateKeyType = "RSA PRIVATE KEY"
	pkcs8PrivateKeyType = "PRIVATE KEY"
)

// RSAPrivateKey parses an RSA private key given key PEM block.
func RSAPrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, trace.NotFound("no PEM block found")
	}

	switch block.Type {
	case pkcs1PrivateKeyType, pkcs8PrivateKeyType:
	default:
		return nil, trace.BadParameter("unexpected private key PEM type %q", block.Type)
	}

	// The DER format doesn't always exactly match the PEM header, various
	// versions of Teleport and OpenSSL have been guilty of writing PKCS#8
	// data into an "RSA PRIVATE KEY" block or vice-versa, so we just try
	// parsing every DER format. This matches the behavior of [tls.X509KeyPair].
	var preferredErr error
	if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := priv.(type) {
		case *rsa.PrivateKey:
			return key, nil
		default:
			return nil, trace.BadParameter("expected an RSA private key but found %T", key)
		}
	} else if block.Type == pkcs8PrivateKeyType {
		preferredErr = err
	}
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	} else if block.Type == pkcs1PrivateKeyType {
		preferredErr = err
	}

	// If all parse functions returned an error, preferedErr is
	// guaranteed to be set to the error from the parse function that
	// usually matches the PEM block type.
	return nil, trace.Wrap(preferredErr, "parsing private key PEM")
}
