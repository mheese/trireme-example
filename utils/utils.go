package utils

import (
	"encoding/pem"
	"io/ioutil"

	trireme "github.com/aporeto-inc/trireme-lib"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/pkiverifier"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/utils/crypto"
	"github.com/influxdata/influxdb/monitor"
	"go.uber.org/zap"
)

// LoadCompactPKI is a helper method to created a PKI implementation of Trireme
func LoadCompactPKI(keyPath, certPath, caCertPath, caKeyPath string) (trireme.Trireme, monitor.Monitor, monitor.Monitor) (*CompactPKI, error){

	// Load client cert
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	// Load key
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		zap.L().Fatal("Failed to read key PEM")
	}

	// Load CA cert
	caCertPEM, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	caKeyPEM, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	token, err := createTxtToken(caKeyPEM, caCertPEM, certPEM)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	return secrets.NewCompactPKIWithTokenCA(keyPEM, certPEM, caCertPEM, [][]byte{[]byte(caCertPEM)}, token)
}

func createTxtToken(caKeyPEM, caPEM, certPEM []byte) ([]byte, error) {
	caKey, err := crypto.LoadEllipticCurveKey(caKeyPEM)
	if err != nil {
		return nil, err
	}

	clientCert, err := crypto.LoadCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	p := pkiverifier.NewPKIIssuer(caKey)
	token, err := p.CreateTokenFromCertificate(clientCert)
	if err != nil {
		return nil, err
	}
	return token, nil
}
