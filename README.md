# API公私钥管理 

## 概述

用户在调用api时，为了保证安全性，加入了密码学算法进行校验外部调用API的合法性。

## 算法

使用RSA非对称算法。

## 生成公私钥对

客户可以通过多种方式生成公私钥对，如：

- **在线生成**；
- OpenSSL生成；
- 本地工具生成；

客户（第三方系统）将生成的私钥保存好，并使用私钥对调用api的参数数据进行签名，签名数据作为参数调用api。

## **上传公钥相关信息**

客户生成公私钥对后，需要将公钥等相关信息上传到API所在的服务中，服务在收到用户的api请求后，使用客户对应的公私钥信息，对参数进行校验，其中需要上传的信息包括：

- 公钥（标准base64格式）

  ```
  -----BEGIN RSA PUBLIC KEY-----
  MIIBCgKCAQEA6zaLP4nCUoI+3bxc+cN17fNCXdZJU0/hoSnsVvalc2SAzB10pqBf
  2sza/RfU0jWi21XyAFxWSZ2mjfeNmbaYJtsdAEmY3TzUlkW5sSbxzaM5Qn41OPZb
  Bn9ItU6JwqrnAlvUs0uBP08EBvMq43tWW5VJPS3qE9PalNRZ6dtZM4o8zBLWlbwG
  6GsL5E7YJSUMMo9TCozWmXBNWsUcdo3vB8WjbgTs0L89ZocnNIKNlxJJpCR2wmTp
  uWobu2erwnHAHWT3P3peCMal83WUsOQV0uoCEZZZb0kKjrhOO1gqycSavQrYs5Ej
  Cp/27dlE/Jl9mXrO5XO3G4sRNx3S8F681wIDAQAB
  -----END RSA PUBLIC KEY-----
  ```

- 密钥格式

  ```
  const (
  	PKCS1 = "PKCS#1"
  	PKCS8 = "PKCS#8"
  )
  ```

- 签名算法：

  ```
  const (
  	SHA224 = 4
  	SHA256 = 5                    // import crypto/sha256
  	SHA384 = 6                    // import crypto/sha512
  	SHA512 = 7                      // import crypto/sha512
  )
  ```

## 签名

- go

  ```go
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
  ```

- java

- php

## 验签

- go

  ```go
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
  ```

- java

- php

## 完整代码

- go
- java
- php