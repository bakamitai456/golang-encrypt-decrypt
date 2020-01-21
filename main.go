package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func logIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	data := []byte("Hello")
	priv, err := rsaConfigSetup("key.pem", "cert.pem", "")
	var pubKey *rsa.PublicKey = &priv.PublicKey

	hashedContent := sha512.Sum512(data)
	signedData, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA512, hashedContent[:])
	logIfError(err)

	base64Msg := base64.StdEncoding.EncodeToString(signedData)
	signedData2, err := base64.StdEncoding.DecodeString(base64Msg)

	fmt.Println(base64Msg)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hashedContent[:], signedData2)
	logIfError(err)

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	logIfError(err)

	rawData, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encryptedData)
	fmt.Println(string(rawData))
}

func rsaConfigSetup(rsaPrivateKeyLocation, rsaPublicKeyLocation, rsaPrivateKeyPassword string) (*rsa.PrivateKey, error) {
	if rsaPrivateKeyLocation == "" {
		// utils.LogWarn("No RSA Key given, generating temp one", nil)
		return GenRSA(4096)
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		// utils.LogWarn("No RSA private key found, generating temp one", nil)
		return GenRSA(4096)
	}

	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		// utils.LogWarn("RSA private key is of the wrong type", utils.LogFields{
		// 	"Pem Type": privPem.Type,
		// })
	}

	if rsaPrivateKeyPassword != "" {
		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(rsaPrivateKeyPassword))
	} else {
		privPemBytes = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			// utils.LogError("Unable to parse RSA private key, generating a temp one", err, utils.LogFields{})
			return GenRSA(4096)
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		// utils.LogError("Unable to parse RSA private key, generating a temp one", err, utils.LogFields{})
		return GenRSA(4096)
	}

	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		// utils.LogWarn("No RSA public key found, generating temp one", nil)
		return GenRSA(4096)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		// utils.LogError("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key",
		// 	errors.New("rsa public key not in pem format"), utils.LogFields{
		// 		"Public key location": rsaPublicKeyLocation,
		// 	})
		return GenRSA(4096)
	}
	if pubPem.Type != "RSA PUBLIC KEY" {
		// utils.LogWarn("RSA public key is of the wrong type", utils.LogFields{
		// 	"Pem Type": pubPem.Type,
		// })
		return GenRSA(4096)
	}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		// utils.LogError("Unable to parse RSA public key, generating a temp one", err, utils.LogFields{})
		return GenRSA(4096)
	}

	var pubKey *rsa.PublicKey
	pubKey = parsedKey.(*rsa.PublicKey)

	privateKey.PublicKey = rsa.PublicKey(*pubKey)

	return privateKey, nil
}

// GenRSA returns a new RSA key of bits length
func GenRSA(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	// utils.LogFatal("Failed to generate signing key", err, nil)
	return key, err
}
