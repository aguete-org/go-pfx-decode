package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	in       = flag.String("in", "", "pkcs#12 (.pfx, .p12) file  with a private key and a certificate only")
	password = flag.String("pass", "", "to decode the ciphered the pkcs#12 file")
)

func main() {
	flag.Parse()

	if *in == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	extension := filepath.Ext(*in)
	name := (*in)[0 : len(*in)-len(extension)]

	keyFilename := fmt.Sprintf("%s.key", name)
	outcert := fmt.Sprintf("%s.crt", name)
	p12_data, err := ioutil.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, certificate, err := pkcs12.Decode(p12_data, *password) // Note the order of the return values.
	if err != nil {
		log.Fatal(err)
	}

	keyBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	//write private key as pem
	keyFile, err := os.Create(keyFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()
	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Private key saved as %s\n", keyFilename)

	certFilename, err := os.Create(outcert)
	if err != nil {
		log.Fatal(err)
	}
	defer certFilename.Close()
	err = pem.Encode(certFilename, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Cert saved as %s\n", outcert)

	fmt.Printf("Certificate not valid after %s\n", certificate.NotAfter.Format("Jan _2 15:04:05 2006 MST"))

}
