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

from SECRET import SNU_ID, SNU_PW, SNU_NM

def do(sess, data):
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
    
    encrypt_data = seed_cbc_encrypt(data.encode(), passni_key, passni_iv)
    
    return encrypt_data

def sso_login(sess = None, agt_resp = None):
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

    login_key = resp.text.split('id="login_key" name="login_key" value="')[1].split('"')[0]
    ed = do(sess, f'{"login_id":"{SNU_ID}","login_pwd":"{SNU_PW}"}')

    payload = {'user_data': ed.hex(), 'login_key': login_key}
    resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/auth", data=payload)
    
    verif_type = 'mail'    

    payload = {'crtfc_type': 'mail', 'login_key': login_key}
    resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/ajaxUserSend", data=payload)

    verif = input("Verification code ? ")

    payload = {'crtfc_no': verif, 'login_key': login_key, "bypass_check": "true"}
    resp = sess.post("https://nsso.snu.ac.kr/sso/usr/snu/mfa/login/ajaxUserAuthId", data=payload)

    payload = {"user_data": "", "page_lang": "", "login_key": login_key, "pwd_type":""}
    resp =  sess.post("https://nsso.snu.ac.kr/sso/usr/snu/login/link", data=payload)
    pni_login_type = resp.text.split('name="pni_login_type" value="')[1].split('"')[0]
    pni_data = resp.text.split('name="pni_data" value="')[1].split('"')[0]
    action =  resp.text.split('name="loginForm" method="post" action="')[1].split('"')[0]
    
    payload = {"pni_login_type": pni_login_type, "pni_data": pni_data}
    resp = sess.post(action, data=payload)
    
    resp = sess.get("https://my.snu.ac.kr/index.jsp")

    return sess

def save_login(sess):
    cookies = [(i.name, i.value) for i in sess.cookies]
    with open("sess.json", "w") as f:
        json.dump(cookies, f, indent=4)

def etl_login():
    sess = requests.session()

    if os.path.exists("sess.json"):
        with open("sess.json", "r") as f:
            cookies = json.load(f)
        for i in cookies:
            sess.cookies.set(i[0], i[1])
    else:
        sso_login(sess)
        save_login(sess)

    resp = sess.get("https://etl.snu.ac.kr/login")
    
    if "iframe.src=" in resp.text:
        cburl = resp.text.split('iframe.src="')[1].split('"')[0]
    else:
        print(resp.text)
        sso_login(sess, agt_resp=resp)

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
