import json
import os
import sys
import urllib.parse
import re
import base64
import copy
import ipaddress
import socket

from appcore import WORK_DIR

# Loopback port of the Xray API inbound (StatsService) in the final config.
XRAY_API_PORT = 10085
SINGBOX_TUN_CONFIG = "singbox_tun.json"
TUN_MTU = 1500

# ChatGPT uses more than one first-party hostname.  Keep this list in one
# place so routing rules and diagnostics describe the same traffic class.
GPT_DOMAINS = [
    "domain:chatgpt.com",
    "domain:openai.com",
    "domain:oaistatic.com",
    "domain:oaiusercontent.com",
    "domain:oaistatsig.com",
    "domain:ct.sendgrid.net",
    "domain:intercom.io",
    "domain:intercomcdn.com",
    "domain:openaimerge.com",
    "domain:workos.com",
    "domain:workoscdn.com",
    "full:workos.imgix.net",
    "full:challenges.cloudflare.com",
    "full:js.stripe.com",
    "domain:ingest.sentry.io",
    "domain:browser-intake-datadoghq.com",
    "full:humb.apple.com",
]

# These requests judge whether the selected VPN server itself is alive.  They
# must never go through optional WARP, otherwise a temporary Cloudflare/WARP
# failure incorrectly tears down a healthy base Xray connection.
BASE_HEALTH_DOMAINS = [
    "full:cp.cloudflare.com",
    "full:connectivitycheck.gstatic.com",
]


def _bytes_to_text(raw):
    """Decode bytes to text, tolerating UTF-8 and UTF-16 (BOM or not).

    Some subscription panels serve UTF-16 (sometimes base64-wrapped), which
    naive utf-8 decoding turns into null-padded garbage with no visible links.
    """
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(enc)
            if "\x00" not in text:
                return text
        except (UnicodeDecodeError, ValueError):
            continue
    # No BOM: guess UTF-16 endianness from the null-byte pattern.
    try:
        if raw[:1] != b"\x00" and raw[1:2] == b"\x00":
            return raw.decode("utf-16-le", errors="ignore").replace("\x00", "")
        if raw[:1] == b"\x00":
            return raw.decode("utf-16-be", errors="ignore").replace("\x00", "")
    except Exception:
        pass
    return raw.decode("utf-8", errors="ignore").replace("\x00", "").lstrip("\ufeff")


def _decode_base64(data):
    """Decode base64 with padding auto-fix; the payload may itself be UTF-16."""
    try:
        pad = 4 - len(data) % 4
        if pad != 4:
            data += "=" * pad
        return _bytes_to_text(base64.b64decode(data))
    except Exception:
        return ""


def _query_dict(qs):
    """Parse query string into a flat dict (first value only)."""
    parsed = urllib.parse.parse_qs(qs)
    return {k: v[0] if v else "" for k, v in parsed.items()}


def _common_stream_settings(q, network="tcp"):
    """Build streamSettings from a query dict."""
    security = q.get("security", "none") or "none"
    sni = q.get("sni", "")
    fp = q.get("fp", "")
    
    # Current Xray supports XHTTP (including XHTTP + REALITY) natively.
    # `splithttp` is the former share-link name for the same transport.
    effective_network = "xhttp" if network == "splithttp" else network

    stream = {
        "network": effective_network,
        "security": security,
        "sockopt": {"tcpKeepAliveIdle": 15, "tcpNoDelay": True},
    }
    if security in ("tls", "reality"):
        tls = {}
        if sni:
            tls["serverName"] = sni
        if fp:
            tls["fingerprint"] = fp
        if security == "reality":
            pbk = q.get("pbk", "").strip()
            # Validate 32-byte base64 curve25519 public key
            valid_pbk = False
            if pbk:
                try:
                    padded = pbk + '=' * (-len(pbk) % 4)
                    raw = base64.b64decode(padded)
                    if len(raw) == 32:
                        valid_pbk = True
                except Exception:
                    pass

            if valid_pbk:
                reality = {
                    "fingerprint": fp or "firefox",
                    "serverName": sni or "",
                    "publicKey": pbk,
                    "shortId": q.get("sid", ""),
                    "spiderX": q.get("spx", "/"),
                }
                stream["realitySettings"] = reality
            else:
                stream["security"] = "tls"
                stream["tlsSettings"] = tls
        else:
            stream["tlsSettings"] = tls

    if effective_network == "xhttp":
        stream["xhttpSettings"] = {
            "path": q.get("path", "/"),
            "mode": q.get("mode", "auto"),
            "host": q.get("host", ""),
        }
    elif network == "ws":
        stream["wsSettings"] = {
            "path": q.get("path", "/"),
            "headers": {"Host": q.get("host", "")} if q.get("host") else {},
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": q.get("path", "/"),
            "host": q.get("host", ""),
        }
    elif network == "h2":
        stream["httpSettings"] = {
            "path": q.get("path", "/"),
            "host": [q.get("host", "")] if q.get("host") else [],
        }
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif network == "tcp" and q.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [q.get("path", "/")],
                    "headers": {"Host": [q.get("host", "")]} if q.get("host") else {},
                },
            }
        }
    return stream


def parse_vless(url, tag):
    if not url.startswith("vless://"):
        return None
    body = url[8:]
    query = ""
    if "?" in body:
        user_and_host, query_and_name = body.split("?", 1)
        if "#" in query_and_name:
            query, name = query_and_name.split("#", 1)
            name = urllib.parse.unquote(name)
        else:
            query = query_and_name
            name = tag
    else:
        if "#" in body:
            user_and_host, name = body.split("#", 1)
            name = urllib.parse.unquote(name)
        else:
            user_and_host = body
            name = tag

    if "@" not in user_and_host:
        return None
    user, host_port = user_and_host.split("@", 1)
    if ":" not in host_port:
        return None
    host, port = host_port.rsplit(":", 1)
    if not port.isdigit():
        return None

    q = _query_dict(query) if query else {}
    network = q.get("type", "tcp")
    if network not in ("tcp", "kcp", "ws", "http", "h2", "domainsocket", "quic", "grpc", "httpupgrade", "xhttp", "splithttp"):
        return None

    return {
        "tag": tag,
        "protocol": "vless",
        "remark": name,
        "settings": {
            "vnext": [{
                "address": host,
                "port": int(port),
                "users": [{
                    "id": user,
                    "encryption": q.get("encryption", "none"),
                    "flow": q.get("flow", ""),
                }],
            }]
        },
        "streamSettings": _common_stream_settings(q, network),
    }


def parse_vmess(url, tag):
    if not url.startswith("vmess://"):
        return None
    data = _decode_base64(url[8:])
    if not data:
        return None
    try:
        cfg = json.loads(data)
    except Exception:
        return None

    host = cfg.get("add", "")
    port = cfg.get("port", 0)
    try:
        port = int(port)
    except Exception:
        return None
    if not host or not port:
        return None

    network = cfg.get("net", "tcp")
    q = {
        "security": cfg.get("tls", ""),
        "sni": cfg.get("sni", ""),
        "fp": cfg.get("fp", ""),
        "path": cfg.get("path", "/"),
        "host": cfg.get("host", ""),
        "serviceName": cfg.get("path", ""),
        "headerType": cfg.get("type", ""),
    }

    # aid may arrive as "", None or a non-numeric string in the wild.
    try:
        alter_id = int(cfg.get("aid", 0) or 0)
    except (TypeError, ValueError):
        alter_id = 0

    return {
        "tag": tag,
        "protocol": "vmess",
        "remark": cfg.get("ps", tag),
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": cfg.get("id", ""),
                    "alterId": alter_id,
                    "security": cfg.get("scy", "auto"),
                }],
            }]
        },
        "streamSettings": _common_stream_settings(q, network),
    }


def parse_trojan(url, tag):
    if not url.startswith("trojan://"):
        return None
    body = url[9:]
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    else:
        name = tag

    parsed = urllib.parse.urlparse("trojan://" + body)
    host = parsed.hostname
    port = parsed.port or 443
    password = parsed.username
    if not host or not password:
        return None

    q = _query_dict(parsed.query)
    network = q.get("type", "tcp")
    return {
        "tag": tag,
        "protocol": "trojan",
        "remark": name,
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "password": password,
            }]
        },
        "streamSettings": _common_stream_settings(q, network),
    }


def parse_shadowsocks(url, tag):
    if not url.startswith("ss://"):
        return None
    body = url[5:]
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    else:
        name = tag

    parsed = urllib.parse.urlparse("ss://" + body)
    host = parsed.hostname
    port = parsed.port

    if not host or not port:
        decoded_body = _decode_base64(body)
        if decoded_body and "@" in decoded_body:
            parsed = urllib.parse.urlparse("ss://" + decoded_body)
            host = parsed.hostname
            port = parsed.port

    if not host or not port:
        return None

    userinfo = urllib.parse.unquote(parsed.username or "")
    if parsed.password:
        method = userinfo
        password = urllib.parse.unquote(parsed.password)
    elif userinfo and ":" in userinfo:
        method, password = userinfo.split(":", 1)
    else:
        decoded = _decode_base64(userinfo)
        if ":" not in decoded:
            return None
        method, password = decoded.split(":", 1)

    return {
        "tag": tag,
        "protocol": "shadowsocks",
        "remark": name,
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
            }]
        },
        "streamSettings": _common_stream_settings({}, "tcp"),
    }


COUNTRY_MAP = [
    ("🇷🇺", "Россия", ("🇷🇺", "RU", "RUSSIA", "RUSSIAN", "РОССИЯ", "МОСКВА", "MOSCOW", "SPB", "СПБ")),
    ("🇩🇪", "Германия", ("🇩🇪", "DE", "GERMANY", "GERMAN", "FRANKFURT", "BERLIN", "ГЕРМАНИЯ")),
    ("🇺🇸", "США", ("🇺🇸", "US", "USA", "UNITED STATES", "AMERICA", "NEW YORK", "LOS ANGELES", "MIAMI", "США")),
    ("🇳🇱", "Нидерланды", ("🇳🇱", "NL", "NETHERLANDS", "DUTCH", "AMSTERDAM", "НИДЕРЛАНДЫ")),
    ("🇫🇮", "Финляндия", ("🇫🇮", "FI", "FINLAND", "HELSINKI", "ФИНЛЯНДИЯ")),
    ("🇹🇷", "Турция", ("🇹🇷", "TR", "TURKEY", "TURKISH", "ISTANBUL", "ТУРЦИЯ")),
    ("🇬🇧", "Великобритания", ("🇬🇧", "GB", "UK", "UNITED KINGDOM", "ENGLAND", "LONDON", "АНГЛИЯ")),
    ("🇫🇷", "Франция", ("🇫🇷", "FR", "FRANCE", "FRENCH", "PARIS", "ФРАНЦИЯ")),
    ("🇯🇵", "Япония", ("🇯🇵", "JP", "JAPAN", "JAPANESE", "TOKYO", "ЯПОНИЯ")),
    ("🇸🇬", "Сингапур", ("🇸🇬", "SG", "SINGAPORE", "СИНГАПУР")),
    ("🇰🇷", "Корея", ("🇰🇷", "KR", "KOREA", "KOREAN", "SEOUL", "КОРЕЯ")),
    ("🇰🇿", "Казахстан", ("🇰🇿", "KZ", "KAZAKHSTAN", "ALMATY", "ASTANA", "КАЗАХСТАН")),
    ("🇸🇪", "Швеция", ("🇸🇪", "SE", "SWEDEN", "STOCKHOLM", "ШВЕЦИЯ")),
    ("🇵🇱", "Польша", ("🇵🇱", "PL", "POLAND", "WARSAW", "ПОЛЬША")),
    ("🇨🇦", "Канада", ("🇨🇦", "CA", "CANADA", "TORONTO", "КАНАДА")),
    ("🇨🇭", "Швейцария", ("🇨🇭", "CH", "SWITZERLAND", "ZURICH", "ШВЕЙЦАРИЯ")),
    ("🇮🇹", "Италия", ("🇮🇹", "IT", "ITALY", "ROME", "MILAN", "ИТАЛИЯ")),
    ("🇪🇸", "Испания", ("🇪🇸", "ES", "SPAIN", "MADRID", "ИСПАНИЯ")),
    ("🇦🇺", "Австралия", ("🇦🇺", "AU", "AUSTRALIA", "SYDNEY", "АВСТРАЛИЯ")),
    ("🇮🇳", "Индия", ("🇮🇳", "IN", "INDIA", "MUMBAI", "ИНДИЯ")),
    ("🇧🇷", "Бразилия", ("🇧🇷", "BR", "BRAZIL", "БРАЗИЛИЯ")),
    ("🇺🇦", "Украина", ("🇺🇦", "UA", "UKRAINE", "KYIV", "KIEV", "УКРАИНА")),
    ("🇦🇪", "ОАЭ", ("🇦🇪", "AE", "UAE", "DUBAI", "ОАЭ", "ДУБАЙ")),
    ("🇭🇰", "Гонконг", ("🇭🇰", "HK", "HONG KONG", "HONGKONG", "ГОНКОНГ")),
    ("🇹🇼", "Тайвань", ("🇹🇼", "TW", "TAIWAN", "ТАЙВАНЬ")),
]


def detect_country(server):
    """Detect country flag and name from server remark, address, or tag."""
    if not isinstance(server, dict):
        return "🌐", "Другая"

    remark = server.get("remark", "") or ""
    key = server_key(server)
    text = f"{remark} {key}".upper()

    for flag, name, keywords in COUNTRY_MAP:
        if flag in remark:
            return flag, name

    words = set(re.findall(r'\b[A-Z0-9А-Я]+\b', text))
    for flag, name, keywords in COUNTRY_MAP:
        for kw in keywords:
            if kw in words or (len(kw) > 2 and kw in text):
                return flag, name

    return "🌐", "Другая"


def parse_link(url, tag):
    """Dispatch to the correct parser."""
    if url.startswith("vless://"):
        return parse_vless(url, tag)
    if url.startswith("vmess://"):
        return parse_vmess(url, tag)
    if url.startswith("trojan://"):
        return parse_trojan(url, tag)
    if url.startswith("ss://"):
        return parse_shadowsocks(url, tag)
    return None


def server_key(server):
    """Return a unique, stable address:port key for any parsed server."""
    if not isinstance(server, dict):
        return ""
    addr = server_address(server)
    port = server_port(server)
    if not addr or not port:
        return ""

    extra = ""
    settings = server.get("settings", {})
    vnext = settings.get("vnext", [])
    if vnext and isinstance(vnext[0], dict):
        users = vnext[0].get("users", [])
        if users and isinstance(users[0], dict) and users[0].get("id"):
            extra = str(users[0].get("id"))[:8]
    else:
        srvs = settings.get("servers", [])
        if srvs and isinstance(srvs[0], dict):
            users = srvs[0].get("users", [])
            if users and isinstance(users[0], dict):
                pwd = users[0].get("password") or users[0].get("id")
                if pwd:
                    extra = str(pwd)[:8]

    remark = (server.get("remark") or "").strip()
    if extra:
        return f"{addr}:{port}#{extra}"
    elif remark:
        return f"{addr}:{port}#{remark}"
    return f"{addr}:{port}"


def server_address(server):
    if not isinstance(server, dict):
        return ""
    settings = server.get("settings", {})
    vnext = settings.get("vnext", [])
    if vnext and isinstance(vnext[0], dict):
        return vnext[0].get("address", "")
    srvs = settings.get("servers", [])
    if srvs and isinstance(srvs[0], dict):
        return srvs[0].get("address", "")
    return ""


def server_port(server):
    if not isinstance(server, dict):
        return 0
    settings = server.get("settings", {})
    vnext = settings.get("vnext", [])
    if vnext and isinstance(vnext[0], dict):
        return vnext[0].get("port", 0)
    srvs = settings.get("servers", [])
    if srvs and isinstance(srvs[0], dict):
        return srvs[0].get("port", 0)
    return 0


def save_decoded_subscription(url, output_file="decoded_sub.txt"):
    """Download a subscription URL and save decoded/plain links to output_file.

    Returns a tuple (success: bool, details: str).
    """
    import requests
    if not url:
        return False, "URL is empty"

    headers = {
        "User-Agent": "v2rayN/6.23 (Windows; GibVPN)"
    }

    # Temporarily remove proxy environment variables so requests does not throw
    # InvalidSchema errors when ALL_PROXY=socks5:// is set in the environment.
    env_proxies = {k: os.environ.pop(k) for k in list(os.environ.keys()) if "proxy" in k.lower()}
    r = None
    try:
        try:
            r = requests.get(url, headers=headers, timeout=20)
            r.raise_for_status()
        except Exception as first_err:
            # If direct fetch failed (e.g. site blocked in RU), try via local Xray HTTP proxy
            try:
                r = requests.get(
                    url,
                    headers=headers,
                    proxies={"http": "http://127.0.0.1:10809", "https": "http://127.0.0.1:10809"},
                    timeout=20
                )
                r.raise_for_status()
            except Exception:
                raise first_err
    except requests.exceptions.HTTPError as e:
        return False, f"HTTP error: {e.response.status_code} {e.response.reason}"
    except requests.exceptions.ConnectionError:
        return False, "Connection error: check internet / URL / firewall"
    except requests.exceptions.Timeout:
        return False, "Timeout: server did not respond in 20 seconds"
    except Exception as e:
        return False, f"Download failed: {type(e).__name__}: {e}"
    finally:
        os.environ.update(env_proxies)

    content = _bytes_to_text(r.content).strip()
    if not content:
        return False, "Server returned empty response"

    def _has_links(text):
        return any(
            line.strip().startswith(prefix)
            for line in text.splitlines()
            for prefix in ("vless://", "vmess://", "trojan://", "ss://")
        )

    # If the raw response already contains links, use it as-is (handles comments/headers).
    # Otherwise try base64 decode; only accept the decoded result if it actually contains links.
    decoded = content
    if not _has_links(content):
        b64_decoded = _decode_base64(content)
        if _has_links(b64_decoded):
            decoded = b64_decoded

    urls = []
    # Plain text / base64: one link per line.
    for line in decoded.splitlines():
        line = line.strip().strip("\ufeff\x00").strip()
        if line and any(line.startswith(prefix) for prefix in ("vless://", "vmess://", "trojan://", "ss://")):
            urls.append(line)

    # Some providers return JSON (object or array) containing links.
    if not urls:
        try:
            data = json.loads(decoded)
            candidates = []
            if isinstance(data, list):
                candidates = data
            elif isinstance(data, dict):
                # Common keys used by subscription formats.
                for key in ("servers", "links", "data", "items"):
                    if key in data and isinstance(data[key], list):
                        candidates = data[key]
                        break
            for item in candidates:
                if isinstance(item, str) and any(item.startswith(prefix) for prefix in ("vless://", "vmess://", "trojan://", "ss://")):
                    urls.append(item)
        except Exception:
            pass

    if not urls:
        return False, f"No supported links found (first 120 chars: {content[:120]!r})"

    output_text = "\n".join(urls) + "\n"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_text)
    except Exception as e:
        return False, f"Failed to write {output_file}: {type(e).__name__}: {e}"

    parsed = sum(1 for u in urls if parse_link(u, "probe") is not None)
    return True, f"{len(urls)} lines, {parsed} supported servers"


def read_text_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.readlines()
    except UnicodeDecodeError:
        with open(filepath, 'r', encoding='utf-16') as f:
            return f.readlines()
    except Exception:
        return []


def get_parsed_servers(sub_file="decoded_sub.txt"):
    lines = read_text_file(sub_file)
    urls = [line.strip() for line in lines if line.strip()]

    parsed_servers = []
    for i, url in enumerate(urls):
        tag = f"proxy-{i}"
        try:
            parsed = parse_link(url, tag)
        except Exception:
            # One malformed link must not kill the whole subscription.
            parsed = None
        if parsed:
            parsed_servers.append(parsed)

    return parsed_servers


def generate_test_config(parsed_servers, base_port=11000, config_path=None):
    """Create a disposable Xray configuration for server probes.

    The normal VPN configuration must never be overwritten by a background
    availability check: Xray keeps the old config in memory, but a later
    reconnect would otherwise start the probe-only config without WARP rules.
    ``config_path`` lets the GUI keep probe files separate.  The legacy
    default is retained for standalone diagnostic scripts.
    """
    if not parsed_servers:
        return False

    inbounds = []
    rules = []

    for i, server in enumerate(parsed_servers):
        port = base_port + i
        inbounds.append({
            "tag": f"in-{i}",
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks"
        })
        rules.append({
            "type": "field",
            "inboundTag": [f"in-{i}"],
            "outboundTag": server["tag"]
        })

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": parsed_servers,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        },
        "policy": {
            "levels": {
                "0": {"connIdle": 300}
            }
        }
    }

    config_path = config_path or os.path.join(WORK_DIR, 'config.json')
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    return True


def get_warp_reserved():
    """Parse `reserved` from wgcf-account.toml.

    Handles both TOML list form (`reserved = [1, 2, 3]`) and plain
    comma-separated form (`reserved = '1,2,3'`). Falls back to [0, 0, 0].
    """
    try:
        for line in read_text_file('wgcf-account.toml'):
            line = line.strip()
            if not line.startswith('reserved'):
                continue
            _, _, value = line.partition('=')
            values = [int(x) for x in re.findall(r'-?\d+', value)]
            if values:
                return values[:3]
    except Exception:
        pass
    return [0, 0, 0]


def _find_file_path(filename):
    if os.path.exists(filename):
        return filename
    work_path = os.path.join(WORK_DIR, filename)
    if os.path.exists(work_path):
        return work_path
    return filename


def read_process_route_matchers(filename):
    """Split an application route list into executable names and full paths."""
    names = []
    paths = []
    path = _find_file_path(filename)
    if not os.path.exists(path):
        return {"process_name": names, "process_path": paths}

    for raw_line in read_text_file(path):
        value = raw_line.strip()
        if not value or value.startswith(("#", ";")):
            continue
        value = os.path.expandvars(value.strip('"'))
        target = paths if (os.path.isabs(value) or "\\" in value or "/" in value) else names
        normalized = os.path.normpath(value) if target is paths else value
        if normalized.casefold() not in {item.casefold() for item in target}:
            target.append(normalized)

    # Some desktop clients are a family of executables. Treating steam.exe as
    # only one process leaves its store/login/download helpers on another IP.
    companions = {
        "steam.exe": (
            "steamwebhelper.exe",
            "steamservice.exe",
            "GameOverlayUI.exe",
            "streaming_client.exe",
        ),
    }
    listed_names = {item.casefold() for item in names}
    listed_names.update(os.path.basename(item).casefold() for item in paths)
    for parent_name, child_names in companions.items():
        if parent_name.casefold() not in listed_names:
            continue
        for child_name in child_names:
            if child_name.casefold() not in {item.casefold() for item in names}:
                names.append(child_name)
    return {"process_name": names, "process_path": paths}


def _process_route_rules(filename, outbound):
    """Build separate sing-box rules because different fields are ANDed."""
    matchers = read_process_route_matchers(filename)
    rules = []
    for field in ("process_name", "process_path"):
        if matchers[field]:
            rules.append({
                field: matchers[field],
                "action": "route",
                "outbound": outbound,
            })
    return rules


def read_tun_direct_domain_matchers():
    """Translate Xray-style direct domain entries into sing-box matchers."""
    suffixes = ["ru", "рф", "xn--p1ai", "ру", "xn--p1ag"]
    exact = []
    regex = []
    path = _find_file_path("direct_domains.txt")
    if os.path.exists(path):
        for raw_line in read_text_file(path):
            value = raw_line.strip()
            if not value or value.startswith(("#", ";", "geosite:")):
                continue
            if value.startswith("regexp:"):
                regex.append(value[len("regexp:"):])
                continue
            if value.startswith("full:"):
                exact.append(value[len("full:"):].lstrip("."))
                continue
            if value.startswith("domain:"):
                value = value[len("domain:"):]
            suffixes.append(value.lstrip("."))

    def unique(values):
        result = []
        seen = set()
        for value in values:
            if value and value.casefold() not in seen:
                seen.add(value.casefold())
                result.append(value)
        return result

    return {
        "domain_suffix": unique(suffixes),
        "domain": unique(exact),
        "domain_regex": unique(regex),
    }


def get_warp_settings(profile_path=None):
    """Read a user-owned wgcf WireGuard profile; never use a shared key."""
    path = profile_path or _find_file_path("wgcf-profile.conf")
    if not os.path.exists(path):
        return None
    section = ""
    values = {"interface": {}, "peer": {}}
    try:
        for raw_line in read_text_file(path):
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            key, separator, value = line.partition("=")
            if separator and section in values:
                normalized_key = key.strip().lower()
                # WireGuard profiles may contain Address more than once (IPv4
                # and IPv6). Retain every value instead of overwriting IPv4.
                if normalized_key == "address":
                    values[section].setdefault(normalized_key, []).append(value.strip())
                else:
                    values[section][normalized_key] = value.strip()
        interface = values["interface"]
        peer = values["peer"]
        raw_addresses = interface.get("address", [])
        if isinstance(raw_addresses, str):
            raw_addresses = [raw_addresses]
        addresses = [item.strip() for raw in raw_addresses for item in raw.split(",") if item.strip()]
        if not interface.get("privatekey") or not addresses or not peer.get("publickey") or not peer.get("endpoint"):
            return None
        return {
            "secretKey": interface["privatekey"], "address": addresses,
            "peers": [{"publicKey": peer["publickey"], "endpoint": peer["endpoint"],
                       "allowedIPs": ["0.0.0.0/0", "::/0"], "keepAlive": 15}],
            "reserved": get_warp_reserved(), "mtu": int(interface.get("mtu", "1280")),
        }
    except (OSError, ValueError):
        return None


def _resolved_ip(host):
    """Resolve a tunnel endpoint before Windows routes are changed."""
    value = str(host or "").strip().strip("[]")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        answers = socket.getaddrinfo(
            value, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        return answers[0][4][0] if answers else value
    except OSError:
        return value


def resolved_server_address(server):
    """Return a concrete IPv4 endpoint suitable for a Windows route exclusion."""
    resolved = _resolved_ip(server_address(server))
    try:
        return resolved if ipaddress.ip_address(resolved).version == 4 else ""
    except ValueError:
        return ""


def _pin_server_endpoint(server):
    pinned = copy.deepcopy(server)
    settings = pinned.get("settings", {})
    targets = settings.get("vnext") or settings.get("servers") or []
    if targets and targets[0].get("address"):
        targets[0]["address"] = _resolved_ip(targets[0]["address"])
    return pinned


def _pin_wireguard_endpoint(warp_settings):
    pinned = copy.deepcopy(warp_settings)
    for peer in pinned.get("peers", []):
        endpoint = str(peer.get("endpoint", "")).strip()
        if endpoint.startswith("[") and "]:" in endpoint:
            host, port = endpoint[1:].split("]:", 1)
        elif ":" in endpoint:
            host, port = endpoint.rsplit(":", 1)
        else:
            continue
        resolved = _resolved_ip(host)
        try:
            is_v6 = ipaddress.ip_address(resolved).version == 6
        except ValueError:
            is_v6 = False
        peer["endpoint"] = f"[{resolved}]:{port}" if is_v6 else f"{resolved}:{port}"
    return pinned


def generate_final_config(
    best_server, use_zapret=False, block_quic=True,
    resolve_endpoints=False,
):
    direct_domains = [
        "domain:ru", "domain:рф", "domain:xn--p1ai",
        "domain:ру", "domain:xn--p1ag",
    ]
    if use_zapret:
        # Route YouTube, Discord, Instagram, Twitter, Torrent trackers, AI & Cloud tools
        # through direct outbound so winws.exe (Zapret) intercepts them at 100% ISP speed
        direct_domains.extend([
            "geosite:youtube",
            "domain:googlevideo.com",
            "domain:youtube.com",
            "domain:ytimg.com",
            "domain:youtu.be",
            "geosite:discord",
            "domain:discord.com",
            "domain:discord.gg",
            "domain:discord.media",
            "domain:discordapp.com",
            "domain:discordapp.net",
            "geosite:instagram",
            "domain:instagram.com",
            "domain:cdninstagram.com",
            "domain:facebook.com",
            "domain:fbcdn.net",
            "geosite:twitter",
            "domain:twitter.com",
            "domain:x.com",
            "domain:twimg.com",
            "domain:t.co",
            "domain:rutracker.org",
            "domain:rutor.info",
            "domain:nnmclub.to",
            "domain:lostfilm.tv",
            "domain:notion.so",
            "domain:canva.com",
            "domain:steampowered.com",
            "domain:steamcommunity.com",
        ])

    dd_file = _find_file_path('direct_domains.txt')
    if os.path.exists(dd_file):
        lines = read_text_file(dd_file)
        direct_domains.extend([line.strip() for line in lines if line.strip() and not line.startswith('#')])
    # Drop duplicates (the file may already contain the built-in entries).
    direct_domains = list(dict.fromkeys(direct_domains))

    direct_apps = []
    da_file = _find_file_path('direct_apps.txt')
    if os.path.exists(da_file):
        lines = read_text_file(da_file)
        direct_apps.extend([line.strip() for line in lines if line.strip() and not line.startswith('#')])
    direct_apps = list(dict.fromkeys(direct_apps))

    warp_domains = [
        "geosite:google-gemini",
        "geosite:openai",
        # Gemini authentication and frontend calls move between shared Google
        # domains. They must keep one WARP exit IP for the whole session.
        "geosite:google",
        "domain:ai.com",
        "domain:gemini.com",
        "domain:gemini.google.com",
        "domain:bard.google.com",
        "domain:aistudio.google.com",
        "domain:makersuite.google.com",
        "domain:ai.google.dev",
        "domain:deepmind.google",
        "domain:generativelanguage.googleapis.com",
        # Antigravity 2.0 uses this separate Cloud Code model backend.
        "domain:daily-cloudcode-pa.googleapis.com",
        "domain:gemini.gstatic.com",
        "domain:geller-pa.googleapis.com",
        "domain:alkalimakersuite-pa.clients6.google.com",
        "domain:webchannel-alkalimakersuite-pa.clients6.google.com",
        "domain:proactivebackend-pa.googleapis.com",
        "domain:robinfrontend-pa.googleapis.com",
        "domain:kimi.com",
        "domain:goog",
        "domain:antigravity-unleash.goog",
        "domain:googleapis.com",
        "domain:google.com",
        # NotebookLM and newer Google AI services use the .google top-level
        # domain (for example notebooklm.google), not .google.com.
        "domain:google",
        *GPT_DOMAINS,
    ]
    wd_file = _find_file_path('warp_domains.txt')
    if os.path.exists(wd_file):
        lines = read_text_file(wd_file)
        warp_domains.extend([line.strip() for line in lines if line.strip() and not line.startswith('#')])
    warp_domains = list(dict.fromkeys(warp_domains))

    # Work on a copy so the caller's server dict (kept in memory and saved to
    # settings as manual_server) is not polluted with the rewritten tag.
    best_server = (
        _pin_server_endpoint(best_server)
        if resolve_endpoints else copy.deepcopy(best_server)
    )
    best_server["tag"] = "best-proxy"
    warp_settings = get_warp_settings()
    if warp_settings and resolve_endpoints:
        warp_settings = _pin_wireguard_endpoint(warp_settings)

    outbounds = [
        best_server,
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "blocked", "protocol": "blackhole"},
        {"tag": "api", "protocol": "freedom"}
    ]
    if warp_settings:
        outbounds.insert(1, {
            "tag": "warp-proxy", "protocol": "wireguard",
            "settings": warp_settings,
            "streamSettings": {"sockopt": {"dialerProxy": "best-proxy"}},
        })

    rules = [
        {"type": "field", "outboundTag": "api", "inboundTag": ["api-in"]},
        {
            # This inbound is reserved for Antigravity. Match it before every
            # domain/direct rule so all requests keep one WARP exit address.
            "type": "field",
            "inboundTag": ["warp-socks-in", "warp-http-in"],
            "outboundTag": "warp-proxy" if warp_settings else "best-proxy",
            "network": "tcp,udp",
        },
    ]

    # Xray uses the first matching route.  Put protected AI destinations
    # before user "direct" exceptions: a broad exception such as
    # ``domain:google`` must not silently bypass WARP for Gemini, NotebookLM
    # or Antigravity.
    if warp_settings:
        rules.append({
            "type": "field",
            "inboundTag": ["socks-in", "http-in"],
            "outboundTag": "warp-proxy",
            "domain": warp_domains
        })

    rules.append({
        "type": "field",
        "inboundTag": ["socks-in", "http-in"],
        "outboundTag": "direct",
        "domain": direct_domains
    })

    rules.append({
        "type": "field",
        "inboundTag": ["socks-in", "http-in"],
        "outboundTag": "best-proxy",
        "domain": BASE_HEALTH_DOMAINS,
    })

    if direct_apps:
        rules.append({
            "type": "field",
            "inboundTag": ["socks-in", "http-in"],
            "outboundTag": "direct",
            "process": direct_apps
        })

    if block_quic:
        # Blocking QUIC (UDP 443) forces Youtube & GoogleVideo to instantly use TCP TLS.
        # This prevents 30-second socket hangs when switching VPN servers!
        rules.insert(0, {
            "type": "field",
            "inboundTag": ["socks-in", "http-in"],
            "outboundTag": "blocked",
            "port": "443",
            "network": "udp"
        })

    rules.append({
        "type": "field",
        "inboundTag": ["socks-in", "http-in"],
        "outboundTag": "best-proxy",
        "network": "tcp,udp"
    })

    config = {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
                # In TUN mode sing-box forwards the resolved destination IP.
                # Recover HTTP/TLS SNI so domain-based WARP rules still match
                # Antigravity, NotebookLM, ChatGPT and other AI endpoints.
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "http-in",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "warp-socks-in",
                "port": 10810,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "warp-http-in",
                "port": 10811,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "api-in",
                "port": XRAY_API_PORT,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"}
            }
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        },
        "policy": {
            "levels": {"0": {"connIdle": 300}},
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True
            }
        }
    }

    config_path = os.path.join(WORK_DIR, 'config.json')
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    return True


def generate_tun_config(route_exclude_addresses=None):
    """Generate a full-device TUN config that forwards every packet to Xray.

    Xray still owns server selection and transport.  sing-box only creates the
    Windows virtual adapter, hijacks DNS, and transparently sends TCP/UDP to
    the local SOCKS inbound.
    """
    forced_vpn_rules = _process_route_rules("vpn_apps.txt", "xray-out")
    direct_app_rules = _process_route_rules("direct_apps.txt", "direct")
    direct_domain_matchers = read_tun_direct_domain_matchers()
    direct_domain_rules = []
    for field in ("domain_suffix", "domain", "domain_regex"):
        if direct_domain_matchers[field]:
            direct_domain_rules.append({
                field: direct_domain_matchers[field],
                "action": "route",
                "outbound": "direct",
            })
    config = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [{
                "tag": "remote-dns",
                # Plain DNS over TCP inside the encrypted Xray tunnel avoids
                # the TLS/bootstrap deadlock observed on Windows TUN startup.
                "type": "tcp",
                "server": "1.1.1.1",
                "server_port": 53,
                "detour": "xray-out",
            }],
            "final": "remote-dns",
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "gibvpn-tun",
            # Windows may deny per-interface IPv6 DNS configuration even to an
            # elevated process. IPv4 TUN is sufficient for desktop apps and
            # avoids aborting the entire VPN on those systems.
            "address": ["172.19.0.1/30"],
            # Keep the virtual adapter at the normal Ethernet MTU.  9000 is
            # only fast on a completely jumbo-capable path; through a remote
            # SOCKS/Xray hop it causes fragmentation and slow ChatGPT/media.
            "mtu": TUN_MTU,
            "auto_route": True,
            # Windows strict_route installs a WFP DNS block on every physical
            # interface.  On some builds it also blocks sing-box's own DNS
            # transport and leaves the machine without name resolution.
            "strict_route": False,
            "stack": "system",
        }],
        "outbounds": [
            {"type": "socks", "tag": "xray-out", "server": "127.0.0.1", "server_port": 10808},
            {
                # Xray routes this local entry through WARP. It is selected
                # only by the Antigravity process rule below.
                "type": "socks",
                "tag": "xray-warp-out",
                "server": "127.0.0.1",
                "server_port": 10810,
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {
                    # Without this rule Xray's connection to the remote VPN
                    # server is captured by the TUN and sent back to Xray,
                    # creating a loop that cuts off all Internet access.
                    "process_name": [
                        "xray.exe",
                        "sing-box.exe",
                    ],
                    "action": "route",
                    "outbound": "direct",
                },
                {
                    # Model backends add and rotate hosts, so domain lists are
                    # not enough. Bind all known Antigravity components.
                    "process_name": [
                        "Antigravity.exe",
                        "language_server.exe",
                        "agy.exe",
                        "agy-node.exe",
                    ],
                    "action": "route",
                    "outbound": "xray-warp-out",
                },
                *forced_vpn_rules,
                *direct_app_rules,
                {
                    # Keep this after application rules: an excluded program
                    # that sends DNS itself must also bypass the VPN.
                    "port": 53,
                    "action": "hijack-dns",
                },
                {"action": "hijack-dns", "protocol": "dns"},
                {
                    # Recover HTTP Host, TLS SNI and QUIC server names before
                    # applying domain exclusions at the TUN layer.
                    "action": "sniff",
                    "timeout": "300ms",
                },
                *direct_domain_rules,
            ],
            "final": "xray-out",
        },
    }
    exclusions = []
    for address in route_exclude_addresses or []:
        try:
            ip = ipaddress.ip_address(str(address).strip())
        except ValueError:
            continue
        exclusions.append(f"{ip}/{32 if ip.version == 4 else 128}")
    if exclusions:
        # Keep Xray's physical VPN connection outside the captured default
        # route.  This prevents TUN -> Xray -> TUN recursion at the OS layer.
        config["inbounds"][0]["route_exclude_address"] = exclusions
    config_path = os.path.join(WORK_DIR, SINGBOX_TUN_CONFIG)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    return config_path


def measure_server_speed(port, timeout=8.0):
    """
    Measure download speed (in bytes/sec) through local SOCKS proxy on given port.
    Returns (bytes_per_sec: float, formatted_str: str).
    """
    import time
    import requests

    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}"
    }

    # Do not fall back to 204 endpoints: they return no payload and used to
    # make working servers appear as 0 B/s. Eight MiB is enough to avoid a
    # TCP slow-start result while keeping a server selection quick.
    test_urls = [
        "https://speed.cloudflare.com/__down?bytes=8388608",
        "https://speed.hetzner.de/10MB.bin",
    ]

    s = requests.Session()
    s.trust_env = False

    for url in test_urls:
        try:
            start_time = time.time()
            r = s.get(url, proxies=proxies, timeout=(4.0, timeout), stream=True)
            if r.status_code in (200, 204):
                received = 0
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        received += len(chunk)
                    if received >= 8 * 1024 * 1024 or time.time() - start_time >= timeout:
                        break
                elapsed = max(0.001, time.time() - start_time)
                if received >= 128 * 1024:
                    speed_bps = received / elapsed
                    return speed_bps, fmt_speed(speed_bps)
        except Exception:
            continue

    return 0.0, "FAIL"


def fmt_speed(speed_bps):
    """Format speed in bytes/sec to human readable MB/s or KB/s."""
    if speed_bps <= 0:
        return "FAIL"
    mbps = speed_bps / (1024 * 1024)
    if mbps >= 1.0:
        return f"{mbps:.1f} MB/s"
    kbps = speed_bps / 1024
    return f"{kbps:.0f} KB/s"
