import requests
import urllib3
import hashlib
import json
import time
from urllib import parse
from rsa import Rsa

urllib3.disable_warnings()

timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

usafe_api = {
    "usafe_url": "http://192.168.3.46:10011/interface/api",
    "app_key": "test",
    "secret": "123456",
    "rsa_private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpY9nLOV8t8b4x"
                       "\nlIAv4qwwiPeUz6LKReHCkbOs4nJaOvr1qvvMTcyKK3cdjB5v24VBnyFCQW5Ixvrh\njrXytgb8UTJCiadd8rp"
                       "+YECPEYZa0R7Jt9ul6aN9470VkL28mZcmzwSbd28L6mol\nsyaRH3uu5Vy+57WnXiao+Xii4WKbxu7d0"
                       "/GlfMbu27aegqbMUbPJRp9anDX+C8z8\ntW8VGfeVJ1cNDxhDuIrO68bBuxiB"
                       "+zerhUfhpaDr7srVs0YWBNYGTn7dugPFaAYE\n40JFDa4brMkmoCFMTttBqY7UdUglHLEkT9XJfdBPSXWwg5rvJo2xtt"
                       "+Xh3zZVURd\ncY/NzagDAgMBAAECggEAbrvq1hLUaPmfB1R4FFXPkQ8JIww19JuIgaS0W/HRJbFm\n/BDh"
                       "+OZnL3BIt1UxVJiiXYrEuEaD7Sm/OpML2PYsTOhbvem1MxKJ3jHYIm8ncNlC\nkkYSXj0FdzfZFW8AynlxuZod"
                       "/fAu9RAygiDCtp5pQaWJYveg5iADj/U+auSCjSiH\nqq9ZbB2SaBZti"
                       "/GfEeLWngSsNtKocXuXqhEyS4xUSJUAdnER1ntsH/q3cKmtjk7+\ng0EGXfEgP4nm0qp9q7CmX5tK"
                       "/ZqPnfcDCyMN3KBHo7cEnghuZ19waVBLW9j+uv83\n8JrIBYge5ntKDWiepmG2OQPLuWRvnF0TLJWxy3N3"
                       "+QKBgQDcgiYlUYOZAOYriLvu\nBdmpMMdrvmaCgrAyz5kdQoh9DK6EQSgv8vhMvvU6696nnJywqiPqX3QcKz8BGZlg"
                       "\nLTbXqjceuQF7aW1Zt9x+d+DN1cyQ9AhjNcVg5hI/YgAhAdva9UHJ7lUfw5/YLK2X"
                       "\nM5EkliQDbr92lhSYkTjnQ2SDLwKBgQDEp2pxoc7GiO3/qTpU93qaDsIlxLeVsCrX\nxxVHTrm0lW5CQdbhSoj6q6N"
                       "+Mo4oP5AtX9QqQ7mCaAlBDWAZlS8wActj17/npPOr\ngVoBv9Zq9C776A"
                       "/+MTlCwlB1BmLaYQUykCY2cjnLWmgwQJqT703ASHdNrtkq54um\n5++Bo"
                       "/vDbQKBgQCsl7IDw6mdOHbv3DY8N5gGNYfhbUYPIPuIybSukkUCm8p8+gLa\nhPKUH2MSm0vLJWn/XSx"
                       "/ZfcblT3bPo4uGTWz2CcMhQID9qEAeEi9NFdgxNc5Hcjy\n3kN"
                       "/dJUTx0ESlMHgv9ael01Jb3TNXysADfytBldp2GVEDHRSdlhzquwhQQKBgQCo"
                       "\n6CrzAsm5mK7jIpUpmY7Cd96l1frhJPkHcMWEA8hZpOeZHTfVNdHFjFrW79FOHJpX"
                       "\nfrGaw6S4r2cTasuZ7ZskHsZ1MUBxVCq+qlGGoyElqCoaz828xMar4n58pUmOzDpM"
                       "\nnadUqHOfiD1pBHRAkBA2EYf3PzDkOxCmARykOxbpWQKBgDwoWQipip4s62DXnNmI\nffUnCBHKFJl3hlMwlujG87ip4"
                       "++/qxHx4bcdgA9/JR9zBrIWX7kt6PWV/0aJviZi\n25panNe4jgXcTkrRUUUtJj7tiHsSl6OBZgyfyKoUayo2AzLB"
                       "/gklsTA6NrIu7Rsw\nzsS126HwDrieYqQJj04C0mnU\n-----END PRIVATE KEY-----\n",
    "hash_algorithm": "sha256",
    "key_format": "PKCS8",
}
# print(timestamp)


def sign(app_key, secret, rq_name, rqs):
    """
    rqs: json类型
    """

    rq_params = rqs
    rq_json = json.dumps(rq_params)
    data = parse.quote(rq_json, encoding='utf-8')  # encoding='utf-8'

    params = {
        "app_key": app_key,
        "data": data,
        "format": "json",
        "name": rq_name,
        "timestamp": timestamp,
        "version": "1.0"
    }
    # sign签名 md5加密
    sign_str = ''
    for i in params.items():
        keyvalues = i[0] + i[1]
        sign_str = sign_str + keyvalues
    sign_str = secret + sign_str + secret
    # print("加密对象", source)
    md5 = hashlib.md5()
    md5.update(sign_str.encode('utf-8'))
    new_md5_min = md5.hexdigest()
    new_md5 = new_md5_min.upper()

    sign_result = {"sign": new_md5}
    params.update(sign_result)
    return params


def Payment(order_num, withdrawal_address, chain_type, symbol, remark, user_id, acc_id, acct_key, amount):
    api_url = usafe_api["usafe_url"]
    app_key = usafe_api["app_key"]
    secret = usafe_api["secret"]
    rsa_private_key = usafe_api["rsa_private_key"]
    hash_algorithm = usafe_api["hash_algorithm"]
    key_format = usafe_api["key_format"]
    headers = {"Accept": "application/json"}
    data = {
        "orderNum": order_num,
        "withdrawalAddress": withdrawal_address,
        "chainType": chain_type,
        "symbol": symbol,
        "remark": remark,
        "amount": amount,
        "userId": user_id,
        "accReq": {"accId": acc_id, "acctKey": acct_key},
    }

    # add rsa
    r = Rsa()
    r.setPriKey(rsa_private_key)
    r.setCryptoHash(hash_algorithm)
    r.setKeyFmt(key_format)
    # generate order data
    orderData = 'orderNum:{},amount:{},address:{},userId:{}'.format(order_num, amount, withdrawal_address,
                                                                    user_id).encode('utf-8')
    rsa_sign = r.sign_data(orderData)
    data["rsaSign"] = rsa_sign

    name = "app.general.withdrawalOrderNo"
    params = sign(app_key, secret, name, data)

    res = requests.post(url=api_url, headers=headers, json=params, verify=False)
    return res


if __name__ == '__main__':
    orderNum = "W00000025"
    withdrawalAddress = "TQggA8Gw7WaBi5ZmcCBdxtyjjbtHvGf9bN"
    chainType = "tron"
    symbol = "usdt"
    remark = "remark test"
    userId = "Ta123456"
    accId = "YY20240500001"
    acctKey = "2f206e50cdee40168fc8c0c133bac1a6"
    amount = "66"
    res = Payment(orderNum, withdrawalAddress, chainType, symbol, remark, userId, accId, acctKey, amount)
    result = json.loads(res.content.decode("utf-8"))
    if "0" == result["code"]:
        print("payment successful, msg:{}\n".format(result["msg"]))
    else:
        print("payment failed, msg:{}\n".format(result["msg"]))
