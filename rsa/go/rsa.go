package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	PKCS1 = "PKCS#1"
	PKCS8 = "PKCS#8"
)

type Rsa struct {
	priKey     []byte
	pubKey     []byte
	cryptoHash crypto.Hash
	keyFmt     string
}

func (r *Rsa) SetPriKey(priKey []byte) {
	r.priKey = priKey
}

func (r *Rsa) SetPubKey(pubKey []byte) {
	r.pubKey = pubKey
}

func (r *Rsa) SetCryptoHash(hash crypto.Hash) {
	r.cryptoHash = hash
}

func (r *Rsa) GetPriKey() []byte {
	return r.priKey
}

func (r *Rsa) GetPubKey() []byte {
	return r.pubKey
}

func (r *Rsa) SetKeyFmt(keyFmt string) {
	r.keyFmt = keyFmt
}

// GenRsaKey generates an PKCS#1 RSA keypair of the given bit size in PEM format.
func (r *Rsa) GenRsaKey(bits int, keyFmt string, hash crypto.Hash) (err error) {
	// Generates private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	var derStream []byte
	if PKCS1 == keyFmt {
		derStream = x509.MarshalPKCS1PrivateKey(privateKey)
	} else if PKCS8 == keyFmt {
		if derStream, err = x509.MarshalPKCS8PrivateKey(privateKey); nil != err {
			return errors.New("failed to MarshalPKCS8PrivateKey")
		}
	} else {
		return errors.New("error private key format")
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	r.priKey = pem.EncodeToMemory(block)

	// Generates public key from private key.
	publicKey := &privateKey.PublicKey
	var derPkix []byte
	if PKCS1 == keyFmt {
		derPkix = x509.MarshalPKCS1PublicKey(publicKey)
	} else if PKCS8 == keyFmt {
		if derPkix, err = x509.MarshalPKIXPublicKey(publicKey); nil != err {
			return errors.New("failed to MarshalPKIXPublicKey")
		}
	} else {
		return errors.New("error public key format")
	}

	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	r.pubKey = pem.EncodeToMemory(block)
	r.cryptoHash = hash
	r.keyFmt = keyFmt
	return
}

// GenDataSum Generating data summaries.
func (r *Rsa) GenDataSum(data []byte) (hashed []byte, err error) {
	// MD5 and SHA1 are not supported as they are not secure.
	switch r.cryptoHash {
	case crypto.SHA224:
		h := sha256.Sum224(data)
		hashed = h[:]
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hashed = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		hashed = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		hashed = h[:]
	default:
		err = errors.New("error hash crypto")
	}
	return
}

// RsaSignByHash signs using private key in PEM format.
func (r *Rsa) RsaSignByHash(hashed []byte) (signData []byte, err error) {
	if nil == r.priKey {
		return nil, errors.New("private key is nil")
	}
	block, _ := pem.Decode(r.priKey)
	if block == nil {
		return nil, errors.New("decode private key error")
	}

	var privateKey interface{}
	if PKCS8 == r.keyFmt {
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if privateKey == nil || err != nil {
		return nil, err
	}

	signData, err = rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), r.cryptoHash, hashed)
	return
}

// RsaVerifySign verifies signature using public key in PEM format.
// A valid signature is indicated by returning a nil error.
// Refer to the online verification tool: https://www.metools.info/code/c82.html
func (r *Rsa) RsaVerifySign(data, sig []byte) error {
	if nil == r.pubKey {
		return errors.New("public key is nil")
	}
	block, _ := pem.Decode(r.pubKey)
	if block == nil {
		return errors.New("decode public key error")
	}

	var pub interface{}
	err := errors.New("")
	if PKCS8 == r.keyFmt {
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	} else {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	}
	if err != nil {
		return err
	}

	// SHA1 and MD5 are not supported as they are not secure.
	var hashed []byte
	switch r.cryptoHash {
	case crypto.SHA224:
		h := sha256.Sum224(data)
		hashed = h[:]
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hashed = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		hashed = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		hashed = h[:]
	}
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), r.cryptoHash, hashed, sig)
}

func main() {
	var r Rsa
	hash := crypto.SHA256
	keyFmt := PKCS8
	priKey := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDq088dwHk19Jnk\nyDZuIUKt+52ewfQ+IO7Cz1CeCBC5cDI5ZfxHg3hzkviJQEsrn84vfYTjAqAM6zYR\nKtTD6TT2XQ4HDFsOPMg81k4BwTFPY57YQYEyx8aCxZUe6IncmI38frX+uYmYWgRK\nMDmj+PORKzITGmShpOiX0mJ0ZH4FOBAGRQBWePGH3fM/TtwbQbMSGTxJsSWOEnBZ\nwKqrUtm0s8v/KoL4adkMBnl8PAGgZ6EHjyZva4KaKZO2zHtDeb5Sv9e1qqgvKwRL\nVTgsEPYliKSiFcTESQLoTz6kgwCakOSfMfaLgWoE0BtOEicxtME0LV6p7o8E5MVj\nUbsfN5bDAgMBAAECggEADMxfdj57vLTolZ9TLBxpnxmJZSd//B+Hs8a1x5nRQ4dk\nYrF2wZ+zjGT/C7KdMN2kUKf1eqPgJ47C4xujqKEeBFayVtsAXshxnLM3YYFvLRBV\nDhyVLI3WeWEdt/yyKtDbst5luozP0tBbzylNXZefZWg7x0PB0UzaFRA1J8/O+Hy+\nKjRPRlBEYuB7UNJOP1VBmhCYKNzWW3s19gEChToza/bY+ekz6j4fqAyHcKY4FgQ7\ncNCIXP5OeerYqGF0/UMtm9N0UiY5j1H+YKS8OmH+Xyxkov0uFltrK3YcqK40EKNW\n69VPZR3oALAh3WPuzAWvM8WlAwFGNbun9uhutTG05QKBgQD2alyXTQdUPmkXNuZC\n5z4SVN6Mx2AC+K0VXLwS6LPKONYLYAR8NF0A0gPzKaiOTPCnacu/V0EjGWhZClZi\nVto2+hGkt3J3fJSUj6vzAdL+F3CYj1eC+DqiVKw2MqqqHe3n5M6CrmS1vBRZDcwb\ns8geD/lRxVow21B6hZ2+n76sbwKBgQDz9g+auHaqNqDQ/16GC37TFuyqpn/fjzot\nYLEU1aVz1idKwzwEreaaXIS9yKfrep9gjr/8TSqpc8hwU+P6y2EZi3eohwmvH6Hw\nBBDMJoj6rtjPcn99qhJB7wKfaZnJWjeVKWpgX8vQX2t7hXCFXHeFctCAbd7U2bwF\nNVRO2g9M7QKBgQDo5gJ5Zm6E6y/8pwDfPxxlyx1FRbOzW0KMLEf+Pz6e5TU5LxlO\nI1e7zMO68ibDyGi0csQGJvwDpqH/dkvLSneY+qXuXwyrbm4oM9q7JYA8c/8R0nlN\n6jvQ7eKOnzi67OrNAG9HCHlbY1aADRBbJoMAFuz4omTqRH8+Lke3wdg/tQKBgFkY\nHa7FeyDCfoyVFnIhtJlmn9vanoyIhBiaXVFcjOX26baWAk87KyJoc1nT8+89gwMC\nXv7HN7NWw3ayTGoE6Fsp4fM8Db9U8BD1iyTjVdcnD6sDB6he+ff2T6DkMfOk7POe\ngmjb01Uv49Licqthj4y+14JvnZdiRRYp2bZKUJgpAoGBAPM0shMCH8oBNBBqStZY\nnWcGrfpn3H9OlWbNLYm1MfHt8Ts7YUo/KjJdySklF3mUaJORkhWqcTpjeQ+dINvF\ndoMPBbyBIr6CHeCMrpMOOJqhKXX/53HlLYjnedr2MrRsgZvl510svPW6OK+keynK\nKhIIYEk5zRJYwQ9IBa7u5q7X\n-----END PRIVATE KEY-----\n"

	r.SetPriKey([]byte(priKey))
	r.SetCryptoHash(hash)
	r.SetKeyFmt(keyFmt)

	// Message to be signed
	orgData := "orderNum:W00000025,amount:66,address:TQggA8Gw7WaBi5ZmcCBdxtyjjbtHvGf9bN,userId:Ta123456"
	message := []byte(orgData)
	//fmt.Printf("\nMessage:%s\n", hex.EncodeToString(message))
	hashed, err := r.GenDataSum(message)
	fmt.Printf("\n-------Data Hash:----------\n%s\n", hex.EncodeToString(hashed))

	// The message is signed using the private key
	signature, err := r.RsaSignByHash(hashed)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	fmt.Printf("\n-------Signature:----------\n%s\n", base64.StdEncoding.EncodeToString(signature))
}

func main1() {
	var r Rsa
	keyBits := 2048
	hash := crypto.SHA256
	keyFmt := PKCS1
	// Generate an RSA public and private key pair
	err := r.GenRsaKey(keyBits, keyFmt, hash)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("\n%s\n", string(r.priKey))
	fmt.Printf("\n%s\n", string(r.pubKey))

	// Message to be signed
	orgData := "Hello, world!"
	message := []byte(orgData)
	//fmt.Printf("\nMessage:%s\n", hex.EncodeToString(message))
	hashed, err := r.GenDataSum(message)
	fmt.Printf("\n-------Data Hash:----------\n%s\n", hex.EncodeToString(hashed))

	// The message is signed using the private key
	signature, err := r.RsaSignByHash(hashed)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	fmt.Printf("\n-------Signature:----------\n%s\n", base64.StdEncoding.EncodeToString(signature))

	// Use a public key to verify the signature
	err = r.RsaVerifySign(message, signature)
	if err != nil {
		fmt.Println("\nVerification failed:", err)
		return
	}

	fmt.Println("\nSignature verified successfully!")
}
