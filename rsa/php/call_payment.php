<?php
require_once "Rsa.php";

class Payment {
    // Constants and Settings
    private $httpUrl = "";
    private $method = "POST";
    private $appKey = "123456";
    private $secret = "123456";
    private $privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyDNjeeOjLdoR7\nkOdi5BiS5C8fVvoLoTSkEGNnNJXdJiZ2mPXG5av1DLUT8gvaV0NJmukeG/BXEUHX\nGXxmsMWWwsUvvJIj5x8iHU9osw+SMR0lmjDuohHFY9NTI1ywX1N1r3FmdmMNNTi4\naZHc6Z9omErhplmwv5FUbloiv1yUbcwhHwPVpMU/WsN2enXd7UCfg7sVo0wK7m3J\nRFXs1PkA2CFwfaebQyYDWuREoMzdPRb9H82SA/H7Lb5g876Tk79x4JP2NV5RmLGM\n3TpGp4KtGYiECLjHaTkToW6qIzzkwd5WAc4/84ILR1QcA572l8AQkBcD8ytMZEt8\n4hAjudebAgMBAAECggEBAJp+L0eLHmQ9aGNXro7OYMxElubYr4qbzHN3jOkmZctI\nqSNLQifdbcHpzs2JvuMryMT7V7+6embyIHEmOh1Y0XopcrQjKaNhjlApope0l5RA\nbYwNKNxHYKgoIFwJWQnpDSAWpY1EuFnjjl3lrJ1FUf6N9pupnjWRY+chAbEY3poi\n32Ls2ne+3EF6mKPD+yAWwnstW3ykfFa2y6EmOtziWnMusnVEEXLUYjBI10IqhwhR\nyE8WRgGiSzyGsL5rcRCuZ5HUxE9mSNk/J9daAbqFee/NlNsi14fTzdOvrcliCgAr\n4L3tYXZqnApd15gv1FyMGiR/VMfRUiWiQBNar8CNRcECgYEA6hmGDOHGzLJEc8f6\naP0ENwtG746S73SiSyTy2BRwh+gNSs0vq8Wka1wI6sElPrRVwPXSx4S17zvvH763\nMQ2+OqqgZPrkx0jeXNUWZlGMZ3aIOXFFDRem87tZSaxFEfmXc5FOomE2dmgGSF7i\n1E4d9Mwu1wWXYSMvu6dDXkWCo7ECgYEAwrT8+skTbOdFyW1PqSwQZhCGMtXM+69J\nTn+u53PoDPzXBZ51U4swFohViHyRnifIlfoyruEaxrULOKULefUVz/m7hgTbIKpj\nTAk9/G0lUHkLJJdKPqrtSq+w8vQpqCPaYTdlf/b+b8xyOUwG9TCEtllXujZsdJ9L\niAoCMFhofwsCgYB6gZDc/OoEBOY9kNFCT+X8yDH++yV5mhe0K0nKOigJdy49jtL7\nmRpJ9IfWEe1juwuFRx9eudxbrYmdmzhSu1ZpbREyxvkiMMfs3LY0JUjMfAMdzGDO\nUSpVMh2vqC8dEPhoygnUf/r4S8e956ncYGTczl1UuOBXPQqlsQpYMxgCgQKBgFE2\nvO6+QGQEc495EOk3f/+SlOdPVpkEnEcp6wKPzhLcw7OMTNP0ErLTWxn7G6IkZf5o\nxgs7ybdofK276fWMzPRa7mUQUXZmm9RzZm+L9yyB0KwKjuVk1mV4sw4j2dxQWB6E\nxMmDdM2dMWfE1oIfIrwMuBLr8IEUkKTFx/PybGPRAoGBAKi1pcQJBUCqyX5mKE47\nUdmPIlyRkwuWoUzV5GM0wIfcR+exf0V/HjdAInCfEbgnelFe1ea8IGZsscSbquUT\nndNWcCpwPIIo0oY+1jkS1/MM/xgT5u8afsnVziYtihODk2+qHas8glzcmNEWIKjc\nzpWAe2Ha6aV8GBcHkRvQ5+SC\n-----END PRIVATE KEY-----\n";
    private	$publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsgzY3njoy3aEe5DnYuQY\nkuQvH1b6C6E0pBBjZzSV3SYmdpj1xuWr9Qy1E/IL2ldDSZrpHhvwVxFB1xl8ZrDF\nlsLFL7ySI+cfIh1PaLMPkjEdJZow7qIRxWPTUyNcsF9Tda9xZnZjDTU4uGmR3Omf\naJhK4aZZsL+RVG5aIr9clG3MIR8D1aTFP1rDdnp13e1An4O7FaNMCu5tyURV7NT5\nANghcH2nm0MmA1rkRKDM3T0W/R/NkgPx+y2+YPO+k5O/ceCT9jVeUZixjN06RqeC\nrRmIhAi4x2k5E6FuqiM85MHeVgHOP/OCC0dUHAOe9pfAEJAXA/MrTGRLfOIQI7nX\nmwIDAQAB\n-----END PUBLIC KEY-----\n";

    // Returns current time in a specific format
    function getTime() {
        return date("Y-m-d H:i:s");
    }

    // Generates a MD5 hash in uppercase
    function md5Hash($text) {
        return strtoupper(md5($text));
    }

    // Constructs the sign for the request
    function buildSign($params, $secret) {
        ksort($params);
        $signStr = "";
        foreach ($params as $key => $value) {
            $signStr .= $key . $value;
        }
        $signStr = $secret . $signStr . $secret;
        return $this->md5Hash($signStr);
    }

    // Gets the HTTP request headers
    function getReqHeader() {
        return [
            "Content-Type" => "application/json",
        ];
    }

    // Retrieves the HTTP request body information
    function getReqBody($funcName, $busParams) {
        $busData = urlencode(json_encode($busParams));
        $sign = $this->buildSign($busParams, $this->secret);
        $reqBody = [
            "name" => $funcName,
            "app_key" => $this->appKey,
            "data" => $busData,
            "timestamp" => $this->getTime(),
            "version" => "1.0",
            "access_token" => "",
            "sign" => $sign
        ];

        // Add RSA signature
        $rsa = new Rsa();
        $rsa->setPriKey($this->privateKey);
        $rsa->setPubKey($this->publicKey);
        $rsa->setCryptoHash(OPENSSL_ALGO_SHA256);
        $rsa->setKeyFmt("PKCS#8");

        $reqBody['rsa_sign'] = $rsa->rsaSign($sign);
        return $reqBody;
    }

    // Sends HTTP request to the service
    function sendRequest($url, $method, $headers, $body) {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($body));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);
        if (!$response) {
            return [curl_error($curl), null];
        }
        curl_close($curl);
        return [null, $response];
    }

    // Main Functionality: Payment
    function Payment($from, $to, $value, $token = "") {
        $busParams = [
            "from" => $from,
            "to" => $to,
            "value" => number_format($value, 4, '.', '')
        ];

        $funcName = "assert.payment";
        $reqBody = $this->getReqBody($funcName, $busParams);
        $reqHeader = $this->getReqHeader();
        if (!empty($token)) {
            $reqHeader[] = "Authorization: Bearer " . $token;
        }
        list($error, $resBody) = $this->sendRequest($this->httpUrl, $this->method, $reqHeader, $reqBody);
        if ($error) {
            return ['-1', $error];
        }
        $res = json_decode($resBody, true);
        return [$res['Code'], $res['Msg']];
    }
}

// Example usage
$p = new Payment();
$from = "";
$to = "";
$value = 8.8888;
$result = $p->Payment($from, $to, $value, "");
$code = $result[0];
$msg = $result[1];
if ("0" == $code) {
    echo "payment successful, msg:",$msg;
} else {
    echo "payment failed, msg:",$msg;
}
echo "\n\n";
?>
