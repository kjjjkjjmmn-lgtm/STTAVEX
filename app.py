import json, requests, warnings, random, threading, time, os, binascii
from datetime import datetime
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Pb2 import MajoRLoGinrEq_pb2, MajoRLoGinrEs_pb2, PorTs_pb2
import urllib3

warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ====== مفاتيح التشفير ======
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ====== الألوان ======
class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; PURPLE = '\033[95m'; CYAN = '\033[96m'
    WHITE = '\033[97m'; RESET = '\033[0m'; BOLD = '\033[1m'

def print_status(msg, type="info"):
    now = datetime.now().strftime("%H:%M:%S")
    icons = {"info": "ℹ️", "success": "✅", "error": "❌", "warning": "⚠️", "spam": "💥"}
    colors = {"info": Colors.BLUE, "success": Colors.GREEN, "error": Colors.RED, 
              "warning": Colors.YELLOW, "spam": Colors.PURPLE}
    print(f"{Colors.CYAN}[{now}]{Colors.RESET} {colors.get(type, Colors.WHITE)}[{icons.get(type, '')}]{Colors.RESET} {msg}")

# ====== دوال التشفير (من الكود الأصلي) ======
def encrypt_api(plain_text):
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def Encrypt_ID(player_id):
    try:
        player_id = int(player_id)
        hex_id = hex(player_id)[2:]
        if len(hex_id) % 2 != 0:
            hex_id = "0" + hex_id
        encrypted = binascii.unhexlify(hex_id)[::-1]
        return encrypted.hex()
    except:
        return ""

# ====== دالة ei (Encrypt ID) من الكود الأصلي ======
def ei(x):
    """تشفير الـ ID بنفس طريقة الكود الأصلي"""
    x = int(x)
    dec = ['80','81','82','83','84','85','86','87','88','89','8a','8b','8c','8d','8e','8f',
           '90','91','92','93','94','95','96','97','98','99','9a','9b','9c','9d','9e','9f',
           'a0','a1','a2','a3','a4','a5','a6','a7','a8','a9','aa','ab','ac','ad','ae','af',
           'b0','b1','b2','b3','b4','b5','b6','b7','b8','b9','ba','bb','bc','bd','be','bf',
           'c0','c1','c2','c3','c4','c5','c6','c7','c8','c9','ca','cb','cc','cd','ce','cf',
           'd0','d1','d2','d3','d4','d5','d6','d7','d8','d9','da','db','dc','dd','de','df',
           'e0','e1','e2','e3','e4','e5','e6','e7','e8','e9','ea','eb','ec','ed','ee','ef',
           'f0','f1','f2','f3','f4','f5','f6','f7','f8','f9','fa','fb','fc','fd','fe','ff']
    xxx = ['1','01','02','03','04','05','06','07','08','09','0a','0b','0c','0d','0e','0f',
           '10','11','12','13','14','15','16','17','18','19','1a','1b','1c','1d','1e','1f',
           '20','21','22','23','24','25','26','27','28','29','2a','2b','2c','2d','2e','2f',
           '30','31','32','33','34','35','36','37','38','39','3a','3b','3c','3d','3e','3f',
           '40','41','42','43','44','45','46','47','48','49','4a','4b','4c','4d','4e','4f',
           '50','51','52','53','54','55','56','57','58','59','5a','5b','5c','5d','5e','5f',
           '60','61','62','63','64','65','66','67','68','69','6a','6b','6c','6d','6e','6f',
           '70','71','72','73','74','75','76','77','78','79','7a','7b','7c','7d','7e','7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                sx, y = int(x), (x - int(x)) * 128
                sy, z = int(y), (y - int(y)) * 128
                sz, n = int(z), (z - int(z)) * 128
                sn, m = int(n), (n - int(n)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                sx, y = int(x), (x - int(x)) * 128
                sy, z = int(y), (y - int(y)) * 128
                sz, n = int(z), (z - int(z)) * 128
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
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

# ====== دوال البروتوباف ======
def build_major_login_payload(open_id, access_token, platform_id=2):
    """بناء بايلود MajorLogin باستخدام Pb2"""
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = platform_id
    major_login.client_version = "1.126.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
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

# ====== جلب التوكن من API ======
def get_token_from_api(uid, password):
    """الحصول على JWT token من API"""
    try:
        url = f"https://damar-free-jwt.spcfy.eu/guest?uid={uid}&pw={password}"
        
        response = requests.get(url, timeout=30, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("status") == "success":
                token = data.get("token")
                if token:
                    return token, None
                else:
                    return None, "No token in response"
            else:
                return None, f"API returned: {data}"
        else:
            return None, f"API failed: {response.status_code}"
            
    except Exception as e:
        return None, f"Error: {str(e)}"

# ====== دالة إرسال طلب السبام (بنفس طريقة الكود الأصلي) ======
def send_spam_request(jwt_token, target_uid):
    """إرسال طلب سبام بنفس طريقة الكود الأصلي"""
    try:
        # استخدام ei() لتشفير الـ ID (نفس الكود الأصلي)
        encrypted_id = ei(target_uid)
        
        # بناء البايلود بنفس طريقة الكود الأصلي
        raw = "08c8b5cfea1810" + encrypted_id + "18012008"
        
        # تشفير البايلود
        data = bytes.fromhex(encrypt_api(bytes.fromhex(raw).hex()))
        
        url = "https://clientbp.ggpolarbear.com/RequestAddingFriend"
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
        
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=2)
        
        # 200 = نجاح, 429 = طلبات كثيرة (يعتبر نجاح للسبام)
        return response.status_code in [200, 201, 202, 429]
        
    except Exception as e:
        print_status(f"Send error: {e}", "error")
        return False

# ====== تحميل الحسابات ======
def load_accounts():
    try:
        with open("accs.json", "r") as f:
            accs = json.load(f)
            print_status(f"تم تحميل {len(accs)} حساب", "success")
            return accs
    except FileNotFoundError:
        print_status("ملف accs.json غير موجود!", "error")
        return []
    except json.JSONDecodeError:
        print_status("خطأ في تنسيق accs.json!", "error")
        return []

# ====== المتغيرات العامة ======
active = {}
tokens = {}
accs = load_accounts()

# ====== دالة السبام ======
def spam_loop(target_uid):
    """حلقة السبام بنفس طريقة الكود الأصلي"""
    event = active.get(target_uid)
    if not event:
        return
    
    count = 0
    print_status(f"بدأ السبام على {target_uid}", "spam")
    
    while not event.is_set():
        for acc in accs:
            if event.is_set():
                break
            
            uid = acc.get("uid")
            pw = acc.get("Pw")
            
            if not uid or not pw:
                continue
            
            try:
                # الحصول على JWT token
                if uid not in tokens:
                    token, error = get_token_from_api(uid, pw)
                    if error:
                        print_status(f"{uid}: {error}", "error")
                        continue
                    tokens[uid] = token
                    print_status(f"{uid}: تم الحصول على التوكن", "success")
                
                jwt_token = tokens[uid]
                
                # إرسال طلب سبام
                if send_spam_request(jwt_token, target_uid):
                    count += 1
                    if count % 5 == 0:
                        print_status(f"تم إرسال {count} طلب إلى {target_uid}", "spam")
                else:
                    # إذا فشل، احذف التوكن
                    if uid in tokens:
                        del tokens[uid]
                        print_status(f"{uid}: فشل الطلب، إعادة المحاولة", "warning")
                        
            except Exception as e:
                print_status(f"خطأ في {uid}: {e}", "error")
                if uid in tokens:
                    del tokens[uid]
        
        time.sleep(0.01)  # نفس السرعة في الكود الأصلي
    
    print_status(f"توقف السبام على {target_uid} (إجمالي {count} طلب)", "info")
    if target_uid in active:
        del active[target_uid]

# ====== Routes ======
@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "service": "STRAVEX SPAM API (Original Method)",
        "accounts": len(accs),
        "active_spams": len(active),
        "jwt_api": "https://damar-free-jwt.spcfy.eu/",
        "endpoints": {
            "/spam?uid={uid}": "بدء السبام",
            "/stop?uid={uid}": "إيقاف السبام",
            "/accounts": "عرض الحسابات",
            "/token?uid=&pw=": "جلب توكن",
            "/status": "حالة البوت",
            "/reload": "إعادة تحميل الحسابات"
        }
    })

@app.route('/spam', methods=['GET'])
def start_spam():
    uid = request.args.get("uid", "").strip()
    
    if not uid:
        return jsonify({"ok": False, "error": "uid required"}), 400
    
    if not uid.isdigit():
        return jsonify({"ok": False, "error": "uid must be numeric"}), 400
    
    if uid in active:
        return jsonify({"ok": True, "message": "already spamming", "uid": uid})
    
    if not accs:
        return jsonify({"ok": False, "error": "No accounts loaded. Check accs.json"}), 400
    
    event = threading.Event()
    active[uid] = event
    
    thread = threading.Thread(target=spam_loop, args=(uid,), daemon=True)
    thread.start()
    
    return jsonify({
        "ok": True,
        "message": "spam started",
        "uid": uid,
        "accounts": len(accs)
    })

@app.route('/stop', methods=['GET'])
def stop_spam():
    uid = request.args.get("uid", "").strip()
    
    if not uid:
        return jsonify({"ok": False, "error": "uid required"}), 400
    
    if uid in active:
        active[uid].set()
        return jsonify({"ok": True, "message": "stopping spam", "uid": uid})
    
    return jsonify({"ok": False, "message": "not spamming this uid"})

@app.route('/accounts', methods=['GET'])
def list_accounts():
    active_count = sum(1 for a in accs if a.get("uid") in tokens)
    return jsonify({
        "total": len(accs),
        "active_tokens": active_count,
        "accounts": [{"uid": a.get("uid"), "token_active": a.get("uid") in tokens} for a in accs[:20]]
    })

@app.route('/token', methods=['GET'])
def get_token():
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

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "active_spams": list(active.keys()),
        "active_tokens": len(tokens),
        "loaded_accounts": len(accs)
    })

@app.route('/reload', methods=['GET'])
def reload_accounts():
    global accs
    accs = load_accounts()
    return jsonify({"ok": True, "accounts": len(accs)})

# ====== التشغيل الرئيسي ======
if __name__ == "__main__":
    print("="*60)
    print("  🔥 STRAVEX SPAM API (Original Method) 🔥")
    print("="*60)
    print(f"  📦 حسابات محملة: {len(accs)}")
    print(f"  🌐 تشغيل على: http://0.0.0.0:5000")
    print(f"  🔑 JWT API: https://damar-free-jwt.spcfy.eu/")
    print("="*60)
    print("\n  📌 الروابط:")
    print("  GET /spam?uid={uid}  - بدء السبام")
    print("  GET /stop?uid={uid}  - إيقاف السبام")
    print("  GET /accounts        - عرض الحسابات")
    print("  GET /token?uid=&pw=  - جلب توكن")
    print("  GET /status          - حالة البوت")
    print("  GET /reload          - إعادة تحميل الحسابات")
    print("="*60 + "\n")
    
    app.run(debug=False, host="0.0.0.0", port=5000)