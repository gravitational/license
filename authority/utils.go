package authority

import (
	"encoding/pem"

	"github.com/gravitational/license/constants"

	"github.com/gravitational/trace"
)

func SplitPEM(pemData []byte) (certPEM []byte, keyPEM []byte, err error) {
	block, rest := pem.Decode(pemData)
	for block != nil {
		switch block.Type {
		case constants.CertificatePEMBlock:
			certPEM = pem.EncodeToMemory(block)
		case constants.RSAPrivateKeyPEMBlock:
			keyPEM = pem.EncodeToMemory(block)
		}
		block, rest = pem.Decode(rest)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, trace.BadParameter("cert or key PEM data is missing")
	}
	return certPEM, keyPEM, nil
}
