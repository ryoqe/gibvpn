"""Regional availability checks for the actual Flow page, not HTTP 200 alone."""
import html
import re
import urllib.parse
from html.parser import HTMLParser

FLOW_URL = "https://flow.google.com/"


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.text = []
        self.images = []
        self.refresh = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style", "noscript"):
            self.hidden += 1
        if tag == "img":
            self.images.append(" ".join(attrs.get(k, "") for k in ("alt", "src")))
        if tag == "meta" and attrs.get("http-equiv", "").casefold() == "refresh":
            self.refresh = attrs.get("content", "")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def flow_response_result(response):
    """Return (usable, reason); embedded JS route dictionaries are not blocks."""
    url = (response.url or "").casefold()
    parsed = urllib.parse.urlsplit(url)
    if "unsupported-country" in parsed.path or "location=unsupported" in parsed.query:
        return False, "Flow: страна не поддерживается"
    if parsed.hostname and parsed.hostname.endswith("google.com") and parsed.path.startswith("/sorry"):
        return False, "Google: проверка CAPTCHA / блокировка выхода"
    if response.status_code != 200:
        return False, f"Flow: HTTP {response.status_code}"
    page = _Page()
    body = response.text or ""
    page.feed(body)
    visible = " ".join(" ".join(page.text).casefold().split())
    images = " ".join(page.images).casefold()
    blocked_phrases = (
        "not available in your country", "not available in your region",
        "isn't currently supported in your country", "is not supported in your country",
        "not yet available in your country", "unsupported country",
        "flow is not available", "flow isn't available", "country is not supported",
        "недоступен в вашей стране", "недоступно в вашей стране",
        "не поддерживается в вашей стране", "не поддерживается в вашем регионе",
    )
    if any(phrase in visible or phrase in images for phrase in blocked_phrases):
        return False, "Flow: страница региональной блокировки"
    if "unsupported-country" in images or "unsupported-country" in page.refresh.casefold():
        return False, "Flow: изображение / переход региональной блокировки"
    # Only an executed-looking redirect statement counts; bundled code can
    # mention the unsupported route even on a perfectly normal landing page.
    if re.search(r"(?:window\.)?location(?:\.href\s*=|\s*=|\.replace\(|\.assign\()\s*['\"][^'\"]*unsupported-country", body, re.I):
        return False, "Flow: перенаправление на региональную блокировку"
    if parsed.hostname != "flow.google.com":
        return False, "Flow: конечная страница не подтверждает доступ"
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = html.unescape(title.group(1)).casefold() if title else ""
    if "flow" in title and any(marker in visible for marker in ("sign in", "create", "creative", "войти", "созда")):
        return True, "Flow: открылась обычная страница"
    return False, "Flow: ответ получен, доступ не подтверждён"


# --------------------------------------------------------------------------
# OmniRoute E2E-проверка Antigravity (вторая ступень режима «ИИ»)
#
# Flow-проверка (выше) фильтрует региональные заглушки дёшево, но не отвечает
# на вопрос «даст ли сервер живой ответ модели». Вторая ступень дергает
# локальный OmniRoute (egress которого временно направлен на проверяемый
# канал) и требует реальных ответов модели N раз подряд с замером латентности.
# --------------------------------------------------------------------------

import json as _json
import os as _os
import time as _time
import urllib.error as _uerr
import urllib.request as _ureq
import http.cookiejar as _cjar

def resolve_omni_config(environ=None):
    """Locate the user's local OmniRoute without hardcoding a home directory.

    Defaults match the legacy layout (~/jarvis/...), but every path and the
    base URL can be overridden with GIBVPN_OMNI_* environment variables.
    """
    env = _os.environ if environ is None else environ
    home = _os.path.expanduser("~")
    base_dir = env.get("GIBVPN_OMNI_DIR") or _os.path.join(home, "jarvis")
    return {
        "base": (env.get("GIBVPN_OMNI_BASE") or "http://127.0.0.1:20128").rstrip("/"),
        "model": env.get("GIBVPN_OMNI_MODEL") or "gemini-3.8-flash-medium",
        "key_path": env.get("GIBVPN_OMNI_KEY_PATH")
        or _os.path.join(base_dir, "omni-api-key.txt"),
        "auth_path": env.get("GIBVPN_OMNI_AUTH_PATH")
        or _os.path.join(base_dir, "mcp-gibvpn", "omni-auth.txt"),
    }


_OMNI = resolve_omni_config()
OMNI_BASE = _OMNI["base"]
OMNI_MODEL = _OMNI["model"]
OMNI_KEY_PATH = _OMNI["key_path"]
OMNI_AUTH_PATH = _OMNI["auth_path"]
OMNI_PROXY_BACKUP = "omni_proxy_backup.json"
OMNI_NO_PROXY = _ureq.build_opener(_ureq.ProxyHandler({}))
_OMNI_NO_PROXY = OMNI_NO_PROXY  # алиас: функции ниже используют подчёркнутое имя

_omni_session = None


def omni_available():
    """OmniRoute поднят и файлы ключей на месте. Иначе E2E-ступень пропускается."""
    if not (_os.path.exists(OMNI_KEY_PATH) and _os.path.exists(OMNI_AUTH_PATH)):
        return False
    try:
        with _OMNI_NO_PROXY.open(OMNI_BASE + "/api/settings/proxy", timeout=2) as r:
            return r.status == 200
    except _uerr.HTTPError as e:
        # 401/403 = сервер жив, просто требует сессию — для нас это «доступен».
        return e.code in (401, 403)
    except Exception:
        return False


def _omni_opener():
    """Opener с cookie-сессией дашборда (пароль из OMNI_AUTH_PATH)."""
    global _omni_session
    if _omni_session is not None:
        return _omni_session
    try:
        with open(OMNI_AUTH_PATH, encoding="utf-8-sig") as f:
            password = f.read().strip()
    except OSError:
        password = ""
    if not password:
        raise RuntimeError("нет пароля OmniRoute в " + OMNI_AUTH_PATH)
    jar = _cjar.CookieJar()
    opener = _ureq.build_opener(_ureq.HTTPCookieProcessor(jar), _ureq.ProxyHandler({}))
    req = _ureq.Request(
        OMNI_BASE + "/api/auth/login",
        data=_json.dumps({"password": password}).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"},
    )
    with opener.open(req, timeout=10) as r:
        r.read()
    _omni_session = opener
    return opener


def omni_set_provider_proxy(host, port, ptype):
    """Направить egress провайдера antigravity на проверяемый канал.
    Возвращает прежнее значение (для omni_restore_proxy). Перед изменением
    прежнее значение сохраняется на диск: жёсткое завершение приложения во
    время E2E не должно оставить OmniRoute на мёртвом порту."""
    opener = _omni_opener()
    with opener.open(OMNI_BASE + "/api/settings/proxy", timeout=10) as r:
        current = _json.loads(r.read().decode("utf-8"))
    prev = (current.get("providers") or {}).get("antigravity")
    save_proxy_backup(prev)
    body = _json.dumps({"providers": {"antigravity": {"host": host, "port": port, "type": ptype}}}).encode("utf-8")
    req = _ureq.Request(OMNI_BASE + "/api/settings/proxy", data=body, method="PUT",
                        headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=10) as r:
        r.read()
    return prev


def _proxy_backup_path():
    from appcore import APP_DIR
    return _os.path.join(APP_DIR, OMNI_PROXY_BACKUP)


def save_proxy_backup(prev):
    """Persist the pre-test egress so the next launch can undo a crash."""
    try:
        path = _proxy_backup_path()
        temp_path = path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            _json.dump({"prev": prev}, handle)
        _os.replace(temp_path, path)
    except OSError:
        pass


def load_proxy_backup():
    """Return (exists, prev). Corrupt files are treated as absent."""
    try:
        with open(_proxy_backup_path(), encoding="utf-8") as handle:
            data = _json.load(handle)
        return True, data.get("prev")
    except (OSError, ValueError):
        return False, None


def clear_proxy_backup():
    try:
        _os.remove(_proxy_backup_path())
    except OSError:
        pass


def recover_proxy_backup():
    """Undo an interrupted E2E. Returns 'none', 'restored' or 'pending'."""
    exists, prev = load_proxy_backup()
    if not exists:
        return "none"
    try:
        omni_restore_proxy(prev)
    except Exception:
        return "pending"
    clear_proxy_backup()
    return "restored"


def omni_restore_proxy(prev):
    """Вернуть прежний egress провайдера antigravity (None/пусто = убрать)."""
    opener = _omni_opener()
    body = _json.dumps({"providers": {"antigravity": prev}}).encode("utf-8")
    req = _ureq.Request(OMNI_BASE + "/api/settings/proxy", data=body, method="PUT",
                        headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=10) as r:
        r.read()


def omni_reset_cooldown():
    """Сбросить 24ч-кэш ошибок подключений OmniRoute (после смены канала)."""
    opener = _omni_opener()
    body = _json.dumps({"all": True}).encode("utf-8")
    req = _ureq.Request(OMNI_BASE + "/api/resilience/cooldowns", data=body, method="POST",
                        headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=15) as r:
        r.read()


def omni_e2e_check(repeat=2, timeout=60):
    """Живой ответ модели Antigravity через OmniRoute.

    Возвращает (ok, reason, latency_ms). repeat успехов подряд обязателен;
    пустой ответ считается неудачей."""
    try:
        with open(OMNI_KEY_PATH, encoding="utf-8") as f:
            key = f.read().strip()
    except OSError:
        key = ""
    if not key:
        return False, "нет ключа OmniRoute", None
    payload = _json.dumps({
        "model": OMNI_MODEL,
        "messages": [{"role": "user", "content": "Ответь ровно одним словом: pong"}],
        "max_tokens": 10,
    }).encode("utf-8")
    latencies = []
    for _ in range(max(1, repeat)):
        t0 = _time.time()
        req = _ureq.Request(OMNI_BASE + "/v1/chat/completions", data=payload, method="POST",
                            headers={"Content-Type": "application/json",
                                     "Authorization": "Bearer " + key})
        try:
            with _OMNI_NO_PROXY.open(req, timeout=timeout) as r:
                d = _json.loads(r.read().decode("utf-8"))
        except _uerr.HTTPError as e:
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            if "not supported" in body or "location" in body:
                return False, "регион не поддерживается", None
            return False, f"OmniRoute HTTP {e.code}", None
        except Exception as e:
            return False, f"OmniRoute недоступен ({type(e).__name__})", None
        reply = ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "").strip()
        if not reply:
            return False, "пустой ответ модели", None
        latencies.append(int((_time.time() - t0) * 1000))
    avg = sum(latencies) // len(latencies)
    return True, f"модель ответила {len(latencies)}x, средняя {avg} мс", avg
