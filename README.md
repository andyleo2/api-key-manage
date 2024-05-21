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

支持多种语言，如：

- go

- java

- php

## 验签

支持多种语言，如：

- go
- java
- php

## 完整代码

- go
- java
- php