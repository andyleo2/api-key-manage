<?php
require_once "Rsa.php";

class Payment {
    // Constants and Settings
    private $httpUrl = "http://192.168.3.46:10011/interface/api";
    private $method = "POST";
    private $appKey = "test";
    private $secret = "123456";
    // private $privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyDNjeeOjLdoR7\nkOdi5BiS5C8fVvoLoTSkEGNnNJXdJiZ2mPXG5av1DLUT8gvaV0NJmukeG/BXEUHX\nGXxmsMWWwsUvvJIj5x8iHU9osw+SMR0lmjDuohHFY9NTI1ywX1N1r3FmdmMNNTi4\naZHc6Z9omErhplmwv5FUbloiv1yUbcwhHwPVpMU/WsN2enXd7UCfg7sVo0wK7m3J\nRFXs1PkA2CFwfaebQyYDWuREoMzdPRb9H82SA/H7Lb5g876Tk79x4JP2NV5RmLGM\n3TpGp4KtGYiECLjHaTkToW6qIzzkwd5WAc4/84ILR1QcA572l8AQkBcD8ytMZEt8\n4hAjudebAgMBAAECggEBAJp+L0eLHmQ9aGNXro7OYMxElubYr4qbzHN3jOkmZctI\nqSNLQifdbcHpzs2JvuMryMT7V7+6embyIHEmOh1Y0XopcrQjKaNhjlApope0l5RA\nbYwNKNxHYKgoIFwJWQnpDSAWpY1EuFnjjl3lrJ1FUf6N9pupnjWRY+chAbEY3poi\n32Ls2ne+3EF6mKPD+yAWwnstW3ykfFa2y6EmOtziWnMusnVEEXLUYjBI10IqhwhR\nyE8WRgGiSzyGsL5rcRCuZ5HUxE9mSNk/J9daAbqFee/NlNsi14fTzdOvrcliCgAr\n4L3tYXZqnApd15gv1FyMGiR/VMfRUiWiQBNar8CNRcECgYEA6hmGDOHGzLJEc8f6\naP0ENwtG746S73SiSyTy2BRwh+gNSs0vq8Wka1wI6sElPrRVwPXSx4S17zvvH763\nMQ2+OqqgZPrkx0jeXNUWZlGMZ3aIOXFFDRem87tZSaxFEfmXc5FOomE2dmgGSF7i\n1E4d9Mwu1wWXYSMvu6dDXkWCo7ECgYEAwrT8+skTbOdFyW1PqSwQZhCGMtXM+69J\nTn+u53PoDPzXBZ51U4swFohViHyRnifIlfoyruEaxrULOKULefUVz/m7hgTbIKpj\nTAk9/G0lUHkLJJdKPqrtSq+w8vQpqCPaYTdlf/b+b8xyOUwG9TCEtllXujZsdJ9L\niAoCMFhofwsCgYB6gZDc/OoEBOY9kNFCT+X8yDH++yV5mhe0K0nKOigJdy49jtL7\nmRpJ9IfWEe1juwuFRx9eudxbrYmdmzhSu1ZpbREyxvkiMMfs3LY0JUjMfAMdzGDO\nUSpVMh2vqC8dEPhoygnUf/r4S8e956ncYGTczl1UuOBXPQqlsQpYMxgCgQKBgFE2\nvO6+QGQEc495EOk3f/+SlOdPVpkEnEcp6wKPzhLcw7OMTNP0ErLTWxn7G6IkZf5o\nxgs7ybdofK276fWMzPRa7mUQUXZmm9RzZm+L9yyB0KwKjuVk1mV4sw4j2dxQWB6E\nxMmDdM2dMWfE1oIfIrwMuBLr8IEUkKTFx/PybGPRAoGBAKi1pcQJBUCqyX5mKE47\nUdmPIlyRkwuWoUzV5GM0wIfcR+exf0V/HjdAInCfEbgnelFe1ea8IGZsscSbquUT\nndNWcCpwPIIo0oY+1jkS1/MM/xgT5u8afsnVziYtihODk2+qHas8glzcmNEWIKjc\nzpWAe2Ha6aV8GBcHkRvQ5+SC\n-----END PRIVATE KEY-----\n";
    // private	$publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsgzY3njoy3aEe5DnYuQY\nkuQvH1b6C6E0pBBjZzSV3SYmdpj1xuWr9Qy1E/IL2ldDSZrpHhvwVxFB1xl8ZrDF\nlsLFL7ySI+cfIh1PaLMPkjEdJZow7qIRxWPTUyNcsF9Tda9xZnZjDTU4uGmR3Omf\naJhK4aZZsL+RVG5aIr9clG3MIR8D1aTFP1rDdnp13e1An4O7FaNMCu5tyURV7NT5\nANghcH2nm0MmA1rkRKDM3T0W/R/NkgPx+y2+YPO+k5O/ceCT9jVeUZixjN06RqeC\nrRmIhAi4x2k5E6FuqiM85MHeVgHOP/OCC0dUHAOe9pfAEJAXA/MrTGRLfOIQI7nX\nmwIDAQAB\n-----END PUBLIC KEY-----\n";
    private $privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpY9nLOV8t8b4x\nlIAv4qwwiPeUz6LKReHCkbOs4nJaOvr1qvvMTcyKK3cdjB5v24VBnyFCQW5Ixvrh\njrXytgb8UTJCiadd8rp+YECPEYZa0R7Jt9ul6aN9470VkL28mZcmzwSbd28L6mol\nsyaRH3uu5Vy+57WnXiao+Xii4WKbxu7d0/GlfMbu27aegqbMUbPJRp9anDX+C8z8\ntW8VGfeVJ1cNDxhDuIrO68bBuxiB+zerhUfhpaDr7srVs0YWBNYGTn7dugPFaAYE\n40JFDa4brMkmoCFMTttBqY7UdUglHLEkT9XJfdBPSXWwg5rvJo2xtt+Xh3zZVURd\ncY/NzagDAgMBAAECggEAbrvq1hLUaPmfB1R4FFXPkQ8JIww19JuIgaS0W/HRJbFm\n/BDh+OZnL3BIt1UxVJiiXYrEuEaD7Sm/OpML2PYsTOhbvem1MxKJ3jHYIm8ncNlC\nkkYSXj0FdzfZFW8AynlxuZod/fAu9RAygiDCtp5pQaWJYveg5iADj/U+auSCjSiH\nqq9ZbB2SaBZti/GfEeLWngSsNtKocXuXqhEyS4xUSJUAdnER1ntsH/q3cKmtjk7+\ng0EGXfEgP4nm0qp9q7CmX5tK/ZqPnfcDCyMN3KBHo7cEnghuZ19waVBLW9j+uv83\n8JrIBYge5ntKDWiepmG2OQPLuWRvnF0TLJWxy3N3+QKBgQDcgiYlUYOZAOYriLvu\nBdmpMMdrvmaCgrAyz5kdQoh9DK6EQSgv8vhMvvU6696nnJywqiPqX3QcKz8BGZlg\nLTbXqjceuQF7aW1Zt9x+d+DN1cyQ9AhjNcVg5hI/YgAhAdva9UHJ7lUfw5/YLK2X\nM5EkliQDbr92lhSYkTjnQ2SDLwKBgQDEp2pxoc7GiO3/qTpU93qaDsIlxLeVsCrX\nxxVHTrm0lW5CQdbhSoj6q6N+Mo4oP5AtX9QqQ7mCaAlBDWAZlS8wActj17/npPOr\ngVoBv9Zq9C776A/+MTlCwlB1BmLaYQUykCY2cjnLWmgwQJqT703ASHdNrtkq54um\n5++Bo/vDbQKBgQCsl7IDw6mdOHbv3DY8N5gGNYfhbUYPIPuIybSukkUCm8p8+gLa\nhPKUH2MSm0vLJWn/XSx/ZfcblT3bPo4uGTWz2CcMhQID9qEAeEi9NFdgxNc5Hcjy\n3kN/dJUTx0ESlMHgv9ael01Jb3TNXysADfytBldp2GVEDHRSdlhzquwhQQKBgQCo\n6CrzAsm5mK7jIpUpmY7Cd96l1frhJPkHcMWEA8hZpOeZHTfVNdHFjFrW79FOHJpX\nfrGaw6S4r2cTasuZ7ZskHsZ1MUBxVCq+qlGGoyElqCoaz828xMar4n58pUmOzDpM\nnadUqHOfiD1pBHRAkBA2EYf3PzDkOxCmARykOxbpWQKBgDwoWQipip4s62DXnNmI\nffUnCBHKFJl3hlMwlujG87ip4++/qxHx4bcdgA9/JR9zBrIWX7kt6PWV/0aJviZi\n25panNe4jgXcTkrRUUUtJj7tiHsSl6OBZgyfyKoUayo2AzLB/gklsTA6NrIu7Rsw\nzsS126HwDrieYqQJj04C0mnU\n-----END PRIVATE KEY-----\n";
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
        $reqBody = [
            "name" => $funcName,
            "app_key" => $this->appKey,
            "data" => $busData,
            "timestamp" => $this->getTime(),
            "version" => "1.0",
            "access_token" => ""
        ];
        $sign = $this->buildSign($reqBody, $this->secret);
        $reqBody['sign'] = $sign;
        return $reqBody;
    }

    // Sends HTTP request to the service
    function sendRequest($url, $method, $headers, $body) {

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',               // 设置发送内容类型为JSON
            'Content-Length: ' . strlen(json_encode($body))          // 设置内容长度
        ));
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($body));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);
        if (!$response) {
            return [curl_error($curl), null];
        }
        curl_close($curl);
        return [null, $response];
    }

    function genOrderData($orderNum, $withdrawalAddress, $userId, $amount) {
        return sprintf("orderNum:%s,amount:%s,address:%s,userId:%s", $orderNum, $amount, $withdrawalAddress, $userId);
    }

    // Main Functionality: Payment
    function Payment($orderNum, $withdrawalAddress, $chainType, $symbol, $remark, $amount, $userId, $accId, $acctKey, $token = "") {
        $busParams = [
            "orderNum" =>        $orderNum,
            "withdrawalAddress" => $withdrawalAddress,
            "chainType" =>         $chainType,
            "symbol" =>            $symbol,
            "remark" =>           $remark,
            "amount" =>           $amount,
            "userId" =>          $userId,
            "accReq" =>          [
                "accId" =>  $accId,
                "acctKey" => $acctKey
            ],
        ];

        // Add RSA signature
        $rsa = new Rsa();
        $rsa->setPriKey($this->privateKey);
        // $rsa->setPubKey($this->publicKey);
        $rsa->setCryptoHash(OPENSSL_ALGO_SHA256);
        $rsa->setKeyFmt("PKCS#8");
        $orderData = $this->genOrderData($orderNum, $withdrawalAddress, $userId, $amount);
        // echo "orderData:" . $orderData . "\n";
        $busParams['rsaSign'] = $rsa->rsaSign($orderData);
        // echo "rsaSign:" . $busParams['rsaSign'] . "\n";

        $funcName = "app.general.withdrawalOrderNo";
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
        return [$res['code'], $res['msg']];
        // return [$res];
    }
}

// Example usage
$p = new Payment();
$orderNum = "W00000025";
$withdrawalAddress = "TQggA8Gw7WaBi5ZmcCBdxtyjjbtHvGf9bN";
$chainType = "tron";
$symbol = "usdt";
$remark = "remark test";
$userId = "Ta123456";
$accId = "YY20240500001";
$acctKey = "2f206e50cdee40168fc8c0c133bac1a6";
$amount = "66";

$result = $p->Payment($orderNum, $withdrawalAddress, $chainType, $symbol, $remark, $amount, $userId, $accId, $acctKey, "");
$code = $result[0];
$msg = $result[1];
if ("0" == $code) {
    echo "payment successful, msg:",$msg;
} else {
    echo "payment failed, msg:",$msg;
}
echo "\n\n";
?>
