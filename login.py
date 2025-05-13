import requests
from Crypto.Util.number import bytes_to_long
from binascii import unhexlify
import os
import json
from fastecdsa.curve import P256
from fastecdsa.point import Point
from seed import seed_cbc_encrypt
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from fido import VirtualFidoDevice as FidoDevice

SNU_PW = "" # Unused on Passkey
SNU_ID = ""
SNU_NM = ""

def key_init(sess):
    curve = P256
    n = curve.q
    byte_length = (n.bit_length() + 7) // 8
    rand_bytes = os.urandom(byte_length)
    r = bytes_to_long(rand_bytes)
    rand = (r % (n - 1)) + 1
    client_prikey = format(rand, 'x')
    priv_key_int = int(client_prikey, 16)

    G = Point(curve.gx, curve.gy, curve)
    client_pub = priv_key_int * G

    client_pubkey_x = format(client_pub.x, '064x')
    client_pubkey_y = format(client_pub.y, '064x')
    client_pubkey = client_pubkey_x + client_pubkey_y

    payload = {"user_ec_publickey": client_pubkey}
    response = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/login/init", data=payload)
    response_data = response.json()

    svr_qx = response_data["svr_qx"]
    svr_qy = response_data["svr_qy"]

    svr_qx_int = int(svr_qx, 16)
    svr_qy_int = int(svr_qy, 16)

    server_point = Point(svr_qx_int, svr_qy_int, curve)
    shared_point = server_point * priv_key_int

    calkey_x = format(shared_point.x, '064x')
    calkey_y = format(shared_point.y, '064x')

    client_calkey = calkey_x + calkey_y

    passni_key = unhexlify(client_calkey[:64])
    passni_iv = unhexlify(client_calkey[64:96])

    return passni_iv, passni_key


def encrypt_login(sess, data):
    passni_iv, passni_key = key_init(sess)
    encrypt_data = seed_cbc_encrypt(data.encode(), passni_key, passni_iv)
    return encrypt_data


def sso_register_passkey(sess = None):
    if not sess:
        sess = requests.session()

    payload = {"crtfc_type": "fido2", "lang":  "ko", "return_url": "https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/view", "lnksys_id": "snu-mfa-sso"}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/snu/regist/step", data=payload)

    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/com/ajaxNextKey")
    next_key = resp.text

    payload = {"next_key": next_key, "sel_user_id": "", "lang": "ko", "user_id": SNU_ID, "user_name": "", "user_birth": ""}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/snu/com/ajaxUserIdCheck", data=payload)
    if not (r := resp.json()).get("result"):
        raise Exception(r)

    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/com/ajaxNextKey")
    next_key = resp.text

    payload = {"next_key": next_key, "gubun": "self", "lang": "ko", "crtfc_no": ""}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/com/ajaxSendMail", data=payload)
    if not (r := resp.json()).get("result"):
        raise Exception(r)

    print("Verification Code sent to mail.")
    verif = input("? ")

    payload = {"next_key": next_key, "gubun": "self", "lang": "ko", "crtfc_no": verif}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/snu/com/ajaxValidCrtfcNo", data=payload)
    if not (r := resp.json()).get("result"):
        raise Exception(r)

    payload = {"next_key": next_key, "gubun": "self", "lang": "ko", "crtfc_no": verif}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/snu/regist/step04/fido2", data=payload)

    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/com/ajaxNextKey")
    next_key = resp.text

    payload = {
            "username": "",
            "displayName": "",
            "credentialNickname": "",
            "authenticatorSelection": {
                    "requireResidentKey": False,
                    "authenticatorAttachment": "platform",
                    "userVerification":"preferred"
                },
            "attestation": "direct"
        }

    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/fido2/register", json=payload, headers={"Origin": "https://mfalogin.snu.ac.kr"})
    result = resp.json()
    if result.get("status") != "ok":
        raise Exception(result)

    fido = FidoDevice("snu_fido.json")
    resp = fido.create(result, "https://mfalogin.snu.ac.kr")

    data = {
            "type": resp["type"],
            "id": resp["id"],
            "response": {
                "attestationObject": resp["response"]["attestationObject"],
                "clientDataJSON": resp["response"]["clientDataJSON"],
            },
            "clientExtensionResults": {}
        }
    payload = {"register_data": json.dumps(data)}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/fido2/register/finish", data=payload, headers={"Origin": "https://mfalogin.snu.ac.kr"})
    
    payload = {"next_key": next_key, "type": "fido2", "lang":  "ko"}
    resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/snu/regist/step05", data=payload)


def sso_login(sess = None, agt_resp = None, auth_type = "passkey"):
    if not sess:
        sess = requests.session()

    if not agt_resp:
        resp = sess.get("https://my.snu.ac.kr/SSOService.do")
    else:
        resp = agt_resp

    agt_url = resp.text.split('name="agt_url" value="')[1].split('"')[0]
    agt_r = resp.text.split('name="agt_r" value="')[1].split('"')[0]
    agt_id = resp.text.split('name="agt_id" value="')[1].split('"')[0]

    payload = {"agt_url": agt_url, "agt_r": agt_r, "agt_id": agt_id}
    resp =  sess.post("https://nsso.snu.ac.kr/sso/usr/login/link", data=payload)

    if "login_key" in resp.text:

        login_key = resp.text.split('id="login_key" name="login_key" value="')[1].split('"')[0]

        if auth_type == "passkey":
            key_init(sess)
            payload = {'user_id': SNU_ID, 'crtfc_type': 'fido2', 'login_key': login_key}
            resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/fido2/ajaxIDTokenCreate", data=payload)
            result = resp.json()
            if not result["result"]:
                raise Exception(result)

            id_token = result["id_token"]

            payload = {"id_token": id_token, "userVerification": "preferred"}
            resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/fido2/options", json=payload, headers={"origin": "https://nsso.snu.ac.kr"})
            result = resp.json()
            
            fido = FidoDevice("snu_fido.json")
            try:
                resp = fido.get(result, "https://nsso.snu.ac.kr")
            except FidoDevice.CredNotFoundError:
                sso_register_passkey()
                print("Passkey created, please rerun.")
                return
            
            data = {
                    "type": "public-key",
                    "id":   resp["id"],
                    "response": {
                        "authenticatorData": resp["response"]["authenticatorData"],
                        "clientDataJSON":    resp["response"]["clientDataJSON"],
                        "signature":         resp["response"]["signature"]
                    },
                    "clientExtensionResults": {}
                }
            
            payload = {"user_data": json.dumps(data), "id_token": id_token}
            resp = sess.post("https://mfalogin.snu.ac.kr/mfa/user/fido2/auth", data=payload, headers={"origin": "https://nsso.snu.ac.kr"})
            if not (result := resp.json()).get("result"):
                raise Exception(result)

            payload = {'login_key': login_key}
            resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/fido2/ajaxUserAuthFido2", data=payload)
            if not (result := resp.json()).get("result"):
                raise Exception(result)
            print(resp.json())

        elif auth_type in ["sms", "main"]:

            # Login
            ed = encrypt_login(sess, f'{{"login_id":"{SNU_ID}","login_pwd":"{SNU_PW}"}}')
            payload = {'user_data': ed.hex(), 'login_key': login_key}
            resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/auth", data=payload)

            # 2FA
            payload = {'crtfc_type': auth_type, 'login_key': login_key}
            resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/ajaxUserSend", data=payload)
        
            verif = input("? ")

            payload = {'crtfc_no': verif, 'login_key': login_key, "bypass_check": "true"}
            resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/ajaxUserAuthId", data=payload)

        # Login complete

        payload = {"user_data": "", "page_lang": "", "login_key": login_key, "pwd_type":""}
        resp =  sess.post("https://nsso.snu.ac.kr/sso/usr/snu/login/link", data=payload)

    target =  resp.text.split('name="loginForm" method="post" action="')[1].split('"')[0]
    pni_login_type = resp.text.split('name="pni_login_type" value="')[1].split('"')[0]
    pni_data = resp.text.split('name="pni_data" value="')[1].split('"')[0]

    payload = {"pni_login_type": pni_login_type, "pni_data": pni_data}
    resp = sess.post(target, data=payload)

    return resp


def save_login(sess):
    cookies = [(i.name, i.value) for i in sess.cookies]
    with open("sess.json", "w") as f:
        json.dump(cookies, f, indent=4)


def etl_login():
    sess = requests.session()

    ## Since we automated Passkey, its better to just log-in everytime.
    
    # if os.path.exists("sess.json"):
    #     with open("sess.json", "r") as f:
    #         cookies = json.load(f)
    #     for i in cookies:
    #         sess.cookies.set(i[0], i[1])
    #

    sso = sess.get("https://etl.snu.ac.kr/passni/sso/spLogin.php")
    resp = sso_login(sess, agt_resp=sso)
    # save_login(sess)
    if "gw-cb.php" not in resp.text:
        print(resp.text)
        raise Exception("Login Failed")

    resp = sess.get("https://etl.snu.ac.kr/xn-sso/gw-cb.php")
    if "iframe.src=" in resp.text:
        cburl = resp.text.split('iframe.src="')[1].split('"')[0]

    resp = sess.get(cburl)
    cpar = resp.text.split("window.loginCryption(")[1].split(")")[0]
    ctstr = cpar.split(",")[0].strip().replace('"',"")
    pkstr = cpar.split(",")[1].strip().replace('"',"")

    ct = b64decode(ctstr)
    pk = b64decode(pkstr.split("-----BEGIN RSA PRIVATE KEY-----")[1].split("-----END RSA PRIVATE KEY-----")[0])

    key = RSA.import_key(pk)
    cipher = PKCS1_v1_5.new(key)
    pt = cipher.decrypt(ct, b'')

    payload = {
        "utf8": "✓", "redirect_to_ssl": "1", "after_login_url": "",
        "pseudonym_session[unique_id]": SNU_NM,
        "pseudonym_session[password]": pt.decode(),
        "pseudonym_session[remember_me]": "1"
    }
    resp = sess.post("https://myetl.snu.ac.kr/login/canvas", data=payload, headers={"referer": cburl})

    return sess


if __name__ == "__main__":
    # sso_register_passkey()
    sso_login()
