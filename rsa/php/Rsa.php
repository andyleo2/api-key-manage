<?php
class Rsa {
    private $priKey;
    private $pubKey;
    private $cryptoHash;
    private $keyFmt;

    public function setPriKey($priKey) {
        $this->priKey = $priKey;
    }

    public function setPubKey($pubKey) {
        $this->pubKey = $pubKey;
    }

    public function setCryptoHash($hash) {
        $this->cryptoHash = $hash;
    }

    public function setKeyFmt($keyFmt) {
        $this->keyFmt = $keyFmt;
    }

    public function getPriKey() {
        return $this->priKey;
    }

    public function getPubKey() {
        return $this->pubKey;
    }

    // Generate RSA key pair
    public function genRsaKey($bits, $keyFmt, $cryptoHash) {
        $hashType = "";
        if ($cryptoHash == OPENSSL_ALGO_SHA256) {
            $hashType = "sha256";
        } elseif ($cryptoHash == OPENSSL_ALGO_SHA224) {
            $hashType = "sha224";
        } elseif ($cryptoHash == OPENSSL_ALGO_SHA384) {
            $hashType = "sha384";
        } elseif ($cryptoHash == OPENSSL_ALGO_SHA512) {
            $hashType = "sha512";
        } else {
            throw new Exception("nonsupport hash type");
        }
        $this->cryptoHash = $cryptoHash;
        $config = array(
            "digest_alg" => $hashType,
            "private_key_bits" => $bits,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey);
        $this->priKey = $privateKey;

        $publicKey = openssl_pkey_get_details($res);
        $this->pubKey = $publicKey["key"];
        $this->keyFmt = $keyFmt;
    }

    // Sign data
    public function rsaSign($data) {
        if (empty($this->priKey)) {
            throw new Exception("Private key is nil");
        }
        $signature = '';
        openssl_sign($data, $signature, $this->priKey, $this->cryptoHash); // Customize based on $this->cryptoHash
        return base64_encode($signature);
    }

    // Verify signature
    public function rsaVerifySign($data, $signature) {
        if (empty($this->pubKey)) {
            throw new Exception("Public key is nil");
        }
        $result = openssl_verify($data, base64_decode($signature), $this->pubKey, $this->cryptoHash); // Customize based on $this->cryptoHash
        return $result === 1;
    }
}

// Example usage
// $rsa = new Rsa();
// $rsa->genRsaKey(2048, "PKCS#1", OPENSSL_ALGO_SHA256);
// $priKey = $rsa->getPriKey();
// $pubKey = $rsa->getPubKey();
// echo "\n$priKey\n";
// echo "\n$pubKey\n";
//
// $data = "Hello, world!";
// $signature = $rsa->rsaSign($data);
// echo "Signature: \n$signature\n\n";
//
// $verification = $rsa->rsaVerifySign($data, $signature);
// echo $verification ? "Signature verified successfully!" : "Verification failed!";
// echo "\n\n";
?>
