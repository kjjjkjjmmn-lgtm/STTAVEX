import json, requests, threading, time, os, binascii
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Pb2 import MajoRLoGinrEq_pb2, MajoRLoGinrEs_pb2, PorTs_pb2

app = Flask(__name__)

# ====== مفاتيح التشفير ======
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ====== دوال التشفير ======
def encrypt_api(plain_text):
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def ei(x):
    x = int(x)
    r = bytearray()
    n = int(x)
    while True:
        p = n & 0x7F
        n >>= 7
        if n:
            p |= 0x80
        r.append(p)
        if not n:
            break
    return r.hex()

# ====== دوال Pb2 ======
def build_major_login_payload(open_id, access_token, platform_id=2):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = platform_id
    major_login.client_version = "1.126.1"
    major_login.system_software = "Android OS 9 / API-28"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019116753"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    
    protobuf_raw = major_login.SerializeToString()
    
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(protobuf_raw, AES.block_size)
    encrypted = cipher.encrypt(padded)
    
    return encrypted, protobuf_raw.hex()

# ====== جلب التوكن من API (مع Pb2 كاحتياطي) ======
def get_token_from_api(uid, password):
    try:
        # 1. المحاولة من DAMAR API
        url = f"https://damar-free-jwt.spcfy.eu/guest?uid={uid}&pw={password}"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                token = data.get("token")
                if token:
                    return token, None
        
        # 2. إذا فشل، استخدم Pb2
        try:
            # الحصول على Access Token
            oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {
                "Host": "100067.connect.garena.com",
                "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                "client_id": "100067"
            }
            
            r = requests.post(oauth_url, headers=headers, data=data, timeout=10)
            if r.status_code == 200:
                d = r.json()
                access_token = d.get("access_token")
                open_id = d.get("open_id")
                
                if access_token and open_id:
                    # تجربة منصات مختلفة
                    platforms = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
                    for platform_id in platforms:
                        try:
                            encrypted_payload, _ = build_major_login_payload(open_id, access_token, platform_id)
                            
                            url = "https://loginbp.ggpolarbear.com/MajorLogin"
                            headers = {
                                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                                "Connection": "Keep-Alive",
                                "Accept-Encoding": "gzip",
                                "Content-Type": "application/octet-stream",
                                "X-Unity-Version": "2018.4.11f1",
                                "X-GA": "v1 1",
                                "ReleaseVersion": "OB54"
                            }
                            
                            response = requests.post(url, data=encrypted_payload, headers=headers, timeout=10)
                            
                            if response.status_code == 200:
                                try:
                                    data_dict = response.json()
                                    if data_dict and "token" in data_dict:
                                        return data_dict["token"], None
                                except:
                                    pass
                        except:
                            continue
        except:
            pass
        
        return None, "All methods failed"
        
    except Exception as e:
        return None, str(e)

# ====== إرسال طلب السبام ======
def send_spam_request(jwt_token, target_uid):
    try:
        encrypted_id = ei(target_uid)
        raw = "08c8b5cfea1810" + encrypted_id + "18012008"
        data = bytes.fromhex(encrypt_api(bytes.fromhex(raw).hex()))
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Host": "clientbp.ggpolarbear.com",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
            "Connection": "keep-alive",
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "Accept": "*/*"
        }
        
        response = requests.post("https://clientbp.ggpolarbear.com/RequestAddingFriend", 
                                 headers=headers, data=data, timeout=2)
        return response.status_code in [200, 201, 202, 429]
        
    except:
        return False

# ====== تحميل الحسابات ======
def load_accounts():
    try:
        with open("accs.json", "r") as f:
            return json.load(f)
    except:
        return []

# ====== المتغيرات العامة ======
active = {}
tokens = {}
accs = load_accounts()

# ====== حلقة السبام ======
def spam_loop(target_uid):
    event = active.get(target_uid)
    if not event:
        return
    
    count = 0
    while not event.is_set():
        for acc in accs:
            if event.is_set():
                break
            
            uid = acc.get("uid")
            pw = acc.get("Pw")
            if not uid or not pw:
                continue
            
            try:
                if uid not in tokens:
                    token, error = get_token_from_api(uid, pw)
                    if error:
                        continue
                    tokens[uid] = token
                
                if send_spam_request(tokens[uid], target_uid):
                    count += 1
                else:
                    if uid in tokens:
                        del tokens[uid]
            except:
                if uid in tokens:
                    del tokens[uid]
        
        time.sleep(0.01)
    
    if target_uid in active:
        del active[target_uid]

# ====== Routes ======
@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "service": "STRAVEX SPAM API",
        "accounts": len(accs),
        "active_spams": len(active)
    })

@app.route('/spam')
def start_spam():
    uid = request.args.get("uid", "").strip()
    
    if not uid or not uid.isdigit():
        return jsonify({"ok": False, "error": "uid required"}), 400
    
    if uid in active:
        return jsonify({"ok": True, "message": "already spamming", "uid": uid})
    
    if not accs:
        return jsonify({"ok": False, "error": "No accounts"}), 400
    
    event = threading.Event()
    active[uid] = event
    threading.Thread(target=spam_loop, args=(uid,), daemon=True).start()
    
    return jsonify({"ok": True, "message": "spam started", "uid": uid})

@app.route('/stop')
def stop_spam():
    uid = request.args.get("uid", "").strip()
    
    if not uid:
        return jsonify({"ok": False, "error": "uid required"}), 400
    
    if uid in active:
        active[uid].set()
        return jsonify({"ok": True, "message": "stopping", "uid": uid})
    
    return jsonify({"ok": False, "message": "not spamming"})

@app.route('/accounts')
def list_accounts():
    return jsonify({
        "total": len(accs),
        "accounts": accs
    })

@app.route('/token')
def get_token_route():
    uid = request.args.get("uid", "").strip()
    pw = request.args.get("pw", "").strip()
    
    if not uid or not pw:
        return jsonify({"ok": False, "error": "uid and pw required"}), 400
    
    token, error = get_token_from_api(uid, pw)
    
    if error:
        return jsonify({"ok": False, "error": error}), 400
    
    return jsonify({
        "ok": True,
        "token": token[:50] + "...",
        "uid": uid
    })

@app.route('/status')
def status():
    return jsonify({
        "active_spams": list(active.keys()),
        "active_tokens": len(tokens),
        "loaded_accounts": len(accs)
    })

@app.route('/reload')
def reload_accounts():
    global accs
    accs = load_accounts()
    return jsonify({"ok": True, "accounts": len(accs)})