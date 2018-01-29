/*
Helper code for demonstrating transfering a file over x509 extension covert channel.
Research paper over x509 covert channel: http://vixra.org/abs/1801.0016
Written by: Jason Reaves
ver1 - 2Jan2018

MIT License

Copyright (c) 2018 Jason Reaves

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package helper

import (
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	//	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	//"encoding/asn1"
	//"encoding/hex"
	"encoding/pem"
	//"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

func encryptData(data string) []byte {
	key := make([]byte, 2)
	_, err := rand.Read(key)
	if err != nil {
		log.Println("Random data creation error: ", err)
	}
	c, err := rc4.NewCipher(key)
	enc := make([]byte, len(data))
	c.XORKeyStream(enc, []byte(data))

	//return hex.EncodeToString(enc)
	return append(key, enc...)
}

func DecryptData(data []byte) string {
	key := data[:2]
	c, err := rc4.NewCipher(key)
	if err != nil {
		log.Println("RC4 error: ", err)
	}
	dec := make([]byte, len(data[2:]))
	c.XORKeyStream(dec, data[2:])
	return string(dec[:])
}


func GenCertWithFile(cn string, fdata []byte, priv *rsa.PrivateKey) ([]byte, []byte) {
	return GenCert(cn, fdata, []string{}, priv)
}

func GenCertWithString(cn string, data string, priv *rsa.PrivateKey) ([]byte, []byte) {
	encData := encryptData(data)
	return GenCert(cn, encData, []string{}, priv)
}

func GenCert(cn string, data []byte, crl []string, priv *rsa.PrivateKey) ([]byte, []byte) {
	//extSubKeyId := pkix.Extension{}
	//extSubKeyId.Id = asn1.ObjectIdentifier{2, 5, 29, 14}
	//extSubKeyId.Critical = true
	//extSubKeyId.Value = []byte(`d99962b39e`)

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Country:            []string{"Neuland"},
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"Auto"},
			CommonName:         cn,
		},
		Issuer: pkix.Name{
			Country:            []string{"Neuland"},
			Organization:       []string{"Skynet"},
			OrganizationalUnit: []string{"Computer Emergency Response Team"},
			Locality:           []string{"Neuland"},
			Province:           []string{"Neuland"},
			StreetAddress:      []string{"Mainstreet 23"},
			PostalCode:         []string{"12345"},
			SerialNumber:       "23",
			CommonName:         cn,
		},
		SignatureAlgorithm: x509.SHA512WithRSA,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, 10),
		//SubjectKeyId:          encData,
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//ExtraExtensions: []pkix.Extension{extSubKeyId},
	}
	if len(data) > 0 {
		//encData := encryptData(data)
		//ca.SubjectKeyId = encData
		ca.SubjectKeyId = data
	}
	if len(crl) > 0 {
		ca.CRLDistributionPoints = crl
	}

	//priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Fatalf("create cert failed %#v", err)
		panic("Cert Creation Error")
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca_b,
	})
	ioutil.WriteFile("testcert.pem", ca_b, 0644)
	return certPem, privPem
}

