"""Live test: does Gemini actually work through the WARP chain, or return a stub?

Builds the same config as builder.generate_final_config (best-proxy + WARP
wireguard chained through it), runs xray and fetches gemini.google.com and
the Gemini API through the local SOCKS port. Compares reserved=[0,0,0] with
the account's real reserved bytes.
"""
import json
import os
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import builder  # noqa: E402

SUB_FILE = sys.argv[1] if len(sys.argv) > 1 else "decoded_sub.txt"
RESERVED = json.loads(sys.argv[2]) if len(sys.argv) > 2 else [0, 0, 0]
SERVER_IDX = int(sys.argv[3]) if len(sys.argv) > 3 else 0
PORT = 11081

servers = builder.get_parsed_servers(SUB_FILE)
print(f"parsed {len(servers)} servers from {SUB_FILE}")
if SERVER_IDX >= len(servers):
    print("no such server index")
    sys.exit(1)

best = dict(servers[SERVER_IDX])
best["tag"] = "best-proxy"
print("using server:", best.get("remark"), builder.server_key(best))

warp_domains = json.loads(os.environ.get("WARP_DOMAINS", "null")) or [
    "geosite:google-gemini",
    "geosite:google",
    "domain:gemini.com",
]

config = {
    "log": {"loglevel": "info"},
    "inbounds": [
        {"tag": "http-in", "port": PORT, "listen": "127.0.0.1",
         "protocol": "http"},
    ],
    "outbounds": [
        best,
        {
            "tag": "warp-proxy",
            "protocol": "wireguard",
            "settings": {
                "secretKey": "OB33xBOTHDt8x43dNretOiTcNaV60H/OrhG201aY+m8=",
                "address": ["172.16.0.2/32",
                            "2606:4700:110:8d70:8392:9047:6f07:6a3d/128"],
                "peers": [{
                    "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "endpoint": "engage.cloudflareclient.com:2408",
                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                    "keepAlive": 15,
                }],
                "reserved": RESERVED,
                "mtu": 1280,
            },
            "streamSettings": {"sockopt": {"dialerProxy": "best-proxy"}},
        },
        {"tag": "direct", "protocol": "freedom"},
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {"type": "field", "outboundTag": "warp-proxy", "domain": warp_domains},
            {"type": "field", "outboundTag": "best-proxy", "network": "tcp,udp"},
        ],
    },
}

cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_warp_chain.json")
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

xray = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xray.exe")
proc = subprocess.Popen([xray, "run", "-c", cfg_path],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        cwd=os.path.dirname(xray))
time.sleep(4)

proxies = {"http": f"http://127.0.0.1:{PORT}", "https": f"http://127.0.0.1:{PORT}"}


UA = os.environ.get("UA", "python-requests")
HDRS = {"User-Agent": UA}


def fetch(url, timeout=25):
    try:
        r = requests.get(url, proxies=proxies, timeout=timeout,
                         allow_redirects=False, headers=HDRS)
        return r.status_code, r.headers.get("location", ""), r.text
    except Exception as e:
        return None, "", f"{type(e).__name__}: {e}"


try:
    print(f"reserved={RESERVED}")
    # 1. Is the tunnel up at all? Cloudflare trace tells us warp=on/off and loc.
    code, loc, body = fetch("https://www.cloudflare.com/cdn-cgi/trace")
    if code:
        info = {k: v for k, v in (line.split("=", 1) for line in body.splitlines() if "=" in line)
                if k in ("warp", "loc", "ip")}
        print("trace:", code, info)
    else:
        print("trace: FAIL", body[:200])

    # 2. Gemini web app root: real page or country stub?
    gemini_url = os.environ.get("GEMINI_URL", "https://gemini.google.com/")
    code, loc, body = fetch(gemini_url)
    if code is None:
        print("gemini.google.com: FAIL", body[:200])
    else:
        stub = "isn't currently supported in your country" in body or \
               "not available in your country" in body or \
               "/sorry/" in loc
        print(f"gemini.google.com: {code} redirect={loc[:120]!r} stub={stub} len={len(body)}")
        if code == 200:
            print("gemini page title:", (body.split("<title>")[1].split("</title>")[0]
                                         if "<title>" in body else "?"))

    # 3. Gemini API endpoint (what apps/clients hit).
    code, loc, body = fetch("https://generativelanguage.googleapis.com/")
    print(f"generativelanguage.googleapis.com: {code} len={len(body)}")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
