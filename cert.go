package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	caMaxAge   = 2 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
)

func genCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()
	if !ca.Leaf.IsCA {
		return nil, errors.New("CA cert is not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.SHA512WithRSA,
	}
	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func genKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenCA(name string) (certPEM, keyPEM []byte, err error) {
	key, err := genKeyPair()
	if err != nil {
		return
	}

	now := time.Now().UTC().Add(time.Duration(-48) * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() * 1000),
		Subject:               pkix.Name{Organization: []string{name}, CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		SubjectKeyId:          bigIntHash(key.N),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 1}, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}},
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return
}

// GenerateCert generates a leaf cert from ca.
func GenerateCert(ca *tls.Certificate, hosts ...string) (*tls.Certificate, error) {
	now := time.Now().UTC().Add(time.Duration(-48) * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() * 1000),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now,
		NotAfter:     now.Add(leafMaxAge),
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.Certificate = append(cert.Certificate, x, ca.Leaf.Raw)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
