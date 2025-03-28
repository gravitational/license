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

package constants

import "encoding/asn1"

const (
	// TLSKeyAlgo is default TLS algo used for K8s X509 certs
	TLSKeyAlgo = "rsa"

	// TLSKeySize is default TLS key size used for K8s X509 certs
	TLSKeySize = 2048

	// RSAPrivateKeyPEMBlock is the name of the PEM block where private key is stored
	RSAPrivateKeyPEMBlock = "RSA PRIVATE KEY"

	// CertificatePEMBlock is the name of the PEM block where certificate is stored
	CertificatePEMBlock = "CERTIFICATE"

	// AnonymizationKeyPEMBlock is the name of the PEM block where anonymization key is stored
	AnonymizationKeyPEMBlock = "TELEPORT ANONYMIZATION KEY"

	// LicenseKeyPair is a name of the license key pair
	LicenseKeyPair = "license"

	// LoopbackIP is IP of the loopback interface
	LoopbackIP = "127.0.0.1"

	// LicenseKeyBits used when generating private key for license certificate
	LicenseKeyBits = 2048

	// LicenseOrg is the default name of license subject organization
	LicenseOrg = "gravitational.io"

	// LicenseTimeFormat represents format of expiration time in license payload
	LicenseTimeFormat = "2006-01-02 15:04:05"
)

// LicenseASNExtensionID is an extension ID used when encoding/decoding
// license payload into certificates
var LicenseASN1ExtensionID = asn1.ObjectIdentifier{2, 5, 42}
