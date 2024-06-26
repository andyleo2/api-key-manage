package main

import (
	"crypto"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	httpUrl    = "http://192.168.3.46:10011/interface/api"
	method     = "POST"
	appKey     = "test"
	secret     = "123456"
	cryptoHash = crypto.SHA256
	keyFmt     = PKCS8
	// priKey     = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyDNjeeOjLdoR7\nkOdi5BiS5C8fVvoLoTSkEGNnNJXdJiZ2mPXG5av1DLUT8gvaV0NJmukeG/BXEUHX\nGXxmsMWWwsUvvJIj5x8iHU9osw+SMR0lmjDuohHFY9NTI1ywX1N1r3FmdmMNNTi4\naZHc6Z9omErhplmwv5FUbloiv1yUbcwhHwPVpMU/WsN2enXd7UCfg7sVo0wK7m3J\nRFXs1PkA2CFwfaebQyYDWuREoMzdPRb9H82SA/H7Lb5g876Tk79x4JP2NV5RmLGM\n3TpGp4KtGYiECLjHaTkToW6qIzzkwd5WAc4/84ILR1QcA572l8AQkBcD8ytMZEt8\n4hAjudebAgMBAAECggEBAJp+L0eLHmQ9aGNXro7OYMxElubYr4qbzHN3jOkmZctI\nqSNLQifdbcHpzs2JvuMryMT7V7+6embyIHEmOh1Y0XopcrQjKaNhjlApope0l5RA\nbYwNKNxHYKgoIFwJWQnpDSAWpY1EuFnjjl3lrJ1FUf6N9pupnjWRY+chAbEY3poi\n32Ls2ne+3EF6mKPD+yAWwnstW3ykfFa2y6EmOtziWnMusnVEEXLUYjBI10IqhwhR\nyE8WRgGiSzyGsL5rcRCuZ5HUxE9mSNk/J9daAbqFee/NlNsi14fTzdOvrcliCgAr\n4L3tYXZqnApd15gv1FyMGiR/VMfRUiWiQBNar8CNRcECgYEA6hmGDOHGzLJEc8f6\naP0ENwtG746S73SiSyTy2BRwh+gNSs0vq8Wka1wI6sElPrRVwPXSx4S17zvvH763\nMQ2+OqqgZPrkx0jeXNUWZlGMZ3aIOXFFDRem87tZSaxFEfmXc5FOomE2dmgGSF7i\n1E4d9Mwu1wWXYSMvu6dDXkWCo7ECgYEAwrT8+skTbOdFyW1PqSwQZhCGMtXM+69J\nTn+u53PoDPzXBZ51U4swFohViHyRnifIlfoyruEaxrULOKULefUVz/m7hgTbIKpj\nTAk9/G0lUHkLJJdKPqrtSq+w8vQpqCPaYTdlf/b+b8xyOUwG9TCEtllXujZsdJ9L\niAoCMFhofwsCgYB6gZDc/OoEBOY9kNFCT+X8yDH++yV5mhe0K0nKOigJdy49jtL7\nmRpJ9IfWEe1juwuFRx9eudxbrYmdmzhSu1ZpbREyxvkiMMfs3LY0JUjMfAMdzGDO\nUSpVMh2vqC8dEPhoygnUf/r4S8e956ncYGTczl1UuOBXPQqlsQpYMxgCgQKBgFE2\nvO6+QGQEc495EOk3f/+SlOdPVpkEnEcp6wKPzhLcw7OMTNP0ErLTWxn7G6IkZf5o\nxgs7ybdofK276fWMzPRa7mUQUXZmm9RzZm+L9yyB0KwKjuVk1mV4sw4j2dxQWB6E\nxMmDdM2dMWfE1oIfIrwMuBLr8IEUkKTFx/PybGPRAoGBAKi1pcQJBUCqyX5mKE47\nUdmPIlyRkwuWoUzV5GM0wIfcR+exf0V/HjdAInCfEbgnelFe1ea8IGZsscSbquUT\nndNWcCpwPIIo0oY+1jkS1/MM/xgT5u8afsnVziYtihODk2+qHas8glzcmNEWIKjc\nzpWAe2Ha6aV8GBcHkRvQ5+SC\n-----END PRIVATE KEY-----\n"
	// pubKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsgzY3njoy3aEe5DnYuQY\nkuQvH1b6C6E0pBBjZzSV3SYmdpj1xuWr9Qy1E/IL2ldDSZrpHhvwVxFB1xl8ZrDF\nlsLFL7ySI+cfIh1PaLMPkjEdJZow7qIRxWPTUyNcsF9Tda9xZnZjDTU4uGmR3Omf\naJhK4aZZsL+RVG5aIr9clG3MIR8D1aTFP1rDdnp13e1An4O7FaNMCu5tyURV7NT5\nANghcH2nm0MmA1rkRKDM3T0W/R/NkgPx+y2+YPO+k5O/ceCT9jVeUZixjN06RqeC\nrRmIhAi4x2k5E6FuqiM85MHeVgHOP/OCC0dUHAOe9pfAEJAXA/MrTGRLfOIQI7nX\nmwIDAQAB\n-----END PUBLIC KEY-----\n"

	priKey = "-----BEGIN PRIVATE KEY-----\n" + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpY9nLOV8t8b4x\n" +
		"lIAv4qwwiPeUz6LKReHCkbOs4nJaOvr1qvvMTcyKK3cdjB5v24VBnyFCQW5Ixvrh\n" +
		"jrXytgb8UTJCiadd8rp+YECPEYZa0R7Jt9ul6aN9470VkL28mZcmzwSbd28L6mol\n" +
		"syaRH3uu5Vy+57WnXiao+Xii4WKbxu7d0/GlfMbu27aegqbMUbPJRp9anDX+C8z8\n" +
		"tW8VGfeVJ1cNDxhDuIrO68bBuxiB+zerhUfhpaDr7srVs0YWBNYGTn7dugPFaAYE\n" +
		"40JFDa4brMkmoCFMTttBqY7UdUglHLEkT9XJfdBPSXWwg5rvJo2xtt+Xh3zZVURd\n" +
		"cY/NzagDAgMBAAECggEAbrvq1hLUaPmfB1R4FFXPkQ8JIww19JuIgaS0W/HRJbFm\n" +
		"/BDh+OZnL3BIt1UxVJiiXYrEuEaD7Sm/OpML2PYsTOhbvem1MxKJ3jHYIm8ncNlC\n" +
		"kkYSXj0FdzfZFW8AynlxuZod/fAu9RAygiDCtp5pQaWJYveg5iADj/U+auSCjSiH\n" +
		"qq9ZbB2SaBZti/GfEeLWngSsNtKocXuXqhEyS4xUSJUAdnER1ntsH/q3cKmtjk7+\n" +
		"g0EGXfEgP4nm0qp9q7CmX5tK/ZqPnfcDCyMN3KBHo7cEnghuZ19waVBLW9j+uv83\n" +
		"8JrIBYge5ntKDWiepmG2OQPLuWRvnF0TLJWxy3N3+QKBgQDcgiYlUYOZAOYriLvu\n" +
		"BdmpMMdrvmaCgrAyz5kdQoh9DK6EQSgv8vhMvvU6696nnJywqiPqX3QcKz8BGZlg\n" +
		"LTbXqjceuQF7aW1Zt9x+d+DN1cyQ9AhjNcVg5hI/YgAhAdva9UHJ7lUfw5/YLK2X\n" +
		"M5EkliQDbr92lhSYkTjnQ2SDLwKBgQDEp2pxoc7GiO3/qTpU93qaDsIlxLeVsCrX\n" +
		"xxVHTrm0lW5CQdbhSoj6q6N+Mo4oP5AtX9QqQ7mCaAlBDWAZlS8wActj17/npPOr\n" +
		"gVoBv9Zq9C776A/+MTlCwlB1BmLaYQUykCY2cjnLWmgwQJqT703ASHdNrtkq54um\n" +
		"5++Bo/vDbQKBgQCsl7IDw6mdOHbv3DY8N5gGNYfhbUYPIPuIybSukkUCm8p8+gLa\n" +
		"hPKUH2MSm0vLJWn/XSx/ZfcblT3bPo4uGTWz2CcMhQID9qEAeEi9NFdgxNc5Hcjy\n" +
		"3kN/dJUTx0ESlMHgv9ael01Jb3TNXysADfytBldp2GVEDHRSdlhzquwhQQKBgQCo\n" +
		"6CrzAsm5mK7jIpUpmY7Cd96l1frhJPkHcMWEA8hZpOeZHTfVNdHFjFrW79FOHJpX\n" +
		"frGaw6S4r2cTasuZ7ZskHsZ1MUBxVCq+qlGGoyElqCoaz828xMar4n58pUmOzDpM\n" +
		"nadUqHOfiD1pBHRAkBA2EYf3PzDkOxCmARykOxbpWQKBgDwoWQipip4s62DXnNmI\n" +
		"ffUnCBHKFJl3hlMwlujG87ip4++/qxHx4bcdgA9/JR9zBrIWX7kt6PWV/0aJviZi\n" +
		"25panNe4jgXcTkrRUUUtJj7tiHsSl6OBZgyfyKoUayo2AzLB/gklsTA6NrIu7Rsw\n" +
		"zsS126HwDrieYqQJj04C0mnU\n" +
		"-----END PRIVATE KEY-----\n"
)

// getTime returns the current time formatted as a string
func getTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// buildSign constructs the sign for the request
func buildSign(params map[string]string, secret string) string {
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var signStr string
	for _, k := range keys {
		signStr += k + params[k]
	}
	signStr = secret + signStr + secret
	return strings.ToUpper(md5Hash(signStr))
}

// md5Hash returns the MD5 hash of a string in uppercase
func md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Gets the http request headers
func getReqHeader() map[string]string {
	reqHeader := map[string]string{
		"Content-Type": "application/json",
	}
	return reqHeader
}

// Retrieves the http request body information
func getReqBody(funcName string, busParams map[string]interface{}) map[string]string {
	// Business parameters
	busBytes, _ := json.Marshal(busParams)
	busData := url.QueryEscape(string(busBytes))

	// request body parameters
	reqBody := map[string]string{
		"name":         funcName,
		"app_key":      appKey,
		"data":         busData,
		"timestamp":    getTime(),
		"version":      "1.0",
		"access_token": "",
	}

	// Constructing signature information
	sign := buildSign(reqBody, secret)
	reqBody["sign"] = sign
	return reqBody
}

// sendRequest send http request to the tag service
func sendRequest(url, method string, reqHeader map[string]string, reqBody map[string]string) (error, []byte) {
	reqBodyJSON, _ := json.Marshal(reqBody)
	// fmt.Println(string(reqBodyJSON))

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return err, nil
	}
	for key, value := range reqHeader {
		req.Header.Add(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return err, nil
	}
	defer resp.Body.Close()

	// handle response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return err, nil
	}
	// fmt.Printf("respon:%v\n", string(body))
	return nil, body
}

func genOrderData(orderNum, withdrawalAddress, userId, amount string) string {
	return fmt.Sprintf("orderNum:%s,amount:%s,address:%s,userId:%s", orderNum, amount, withdrawalAddress, userId)
}

// Payment
func Payment(orderNum, withdrawalAddress, chainType, symbol, remark, userId, accId, acctKey, amount string, token string) (code, msg string) {
	type Response struct {
		Code  string
		Msg   string
		ReqId string
	}
	type AccReq struct {
		AccId   string `json:"accId"`
		AcctKey string `json:"acctKey"`
	}
	// api params
	busParams := map[string]interface{}{
		"orderNum":          orderNum,
		"withdrawalAddress": withdrawalAddress,
		"chainType":         chainType,
		"symbol":            symbol,
		"remark":            remark,
		"amount":            amount,
		"userId":            userId,
		"accReq":            AccReq{AccId: accId, AcctKey: acctKey},
	}

	var r Rsa
	r.SetPriKey([]byte(priKey))
	r.SetCryptoHash(cryptoHash)
	r.SetKeyFmt(keyFmt)
	orderData := genOrderData(orderNum, withdrawalAddress, userId, amount)
	hashed, err := r.GenDataSum([]byte(orderData))
	// fmt.Printf("\n-------Data Hash:----------\n%s\n", hex.EncodeToString(hashed))
	signature, err := r.RsaSignByHash(hashed)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	busParams["rsaSign"] = base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("rsaSign:%s\n", busParams["rsaSign"])

	funcName := "app.general.withdrawalOrderNo"
	reqBody := getReqBody(funcName, busParams)
	reqHeader := getReqHeader()
	if "" != token {
		reqHeader["Authorization"] = "Bearer " + token
	}
	// fmt.Printf("Req params:%v\n", busParams)
	err, resBody := sendRequest(httpUrl, method, reqHeader, reqBody)
	if err != nil {
		return "-1", err.Error()
	}
	var res Response
	if err := json.Unmarshal(resBody, &res); err != nil {
		// fmt.Println(err)
		return "-1", err.Error()
	}
	code = res.Code
	msg = res.Msg
	// fmt.Printf("%v\n", res)
	return
}

func TestPayment(t *testing.T) {
	orderNum := "W00000025"
	withdrawalAddress := "TQggA8Gw7WaBi5ZmcCBdxtyjjbtHvGf9bN"
	chainType := "tron"
	symbol := "usdt"
	remark := "remark test"
	userId := "Ta123456"
	accId := "YY20240500001"
	acctKey := "2f206e50cdee40168fc8c0c133bac1a6"
	amount := "66"
	code, msg := Payment(orderNum, withdrawalAddress, chainType, symbol, remark, userId, accId, acctKey, amount, "")
	if "0" == code {
		fmt.Printf("payment successful, msg:%s\n", msg)
	} else {
		fmt.Printf("payment failed, msg:%s\n", msg)
	}
}
