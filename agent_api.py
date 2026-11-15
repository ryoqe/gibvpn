# -*- coding: utf-8 -*-
r"""Локальный control-API GibVPN для ИИ-агента (мост gibvpn-mcp).

Слушает ТОЛЬКО 127.0.0.1:7781. Эндпоинты:
  GET  /status                 — состояние окна/VPN (чтение атрибутов, без Qt-вызовов)
  GET  /servers                — список серверов активной подписки (в GUI-потоке)
  POST /connect  {"server": X} — подключить сервер по имени/хосту/remark
  POST /disconnect             — stop_vpn()
  POST /mode/ai                — штатный подбор «ИИ» (smart_start_auto)
  POST /warp     {"enabled":B} — set_warp_enabled(B)

Ответ всегда application/json. HTTP-поток никогда не трогает Qt напрямую:
действия исполняются в GUI-потоке через BlockingQueuedConnection.

Защита: запрос принимается только с Host 127.0.0.1/localhost и без заголовка
Origin (браузерная страница всегда его присылает, поэтому CSRF невозможен).
Необязательный токен X-GibVPN-Token хранится в %APPDATA%\GibVPN\agent_api.json;
обязательным он становится при GIBVPN_AGENT_REQUIRE_TOKEN=1.
"""
import hmac
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from PyQt6.QtCore import (QObject, pyqtSlot as Slot, QMetaObject, Q_ARG,
                          Q_RETURN_ARG, Qt)

API_PORT = 7781
API_HOST = "127.0.0.1"
TOKEN_HEADER = "X-GibVPN-Token"
REQUIRE_TOKEN_ENV = "GIBVPN_AGENT_REQUIRE_TOKEN"
ALLOWED_HOSTS = {
    API_HOST, "localhost",
    f"{API_HOST}:{API_PORT}", f"localhost:{API_PORT}",
}


def is_authorized(headers, token, require_token=False):
    """Return (allowed, reason) for a local HTTP request.

    Browsers cannot forge Host or omit Origin on cross-origin POST, so these
    two checks stop web-page CSRF and DNS-rebinding attempts. The token is an
    extra layer for clients that can send a custom header.
    """
    host = str(headers.get("Host") or "").strip().lower()
    if host not in ALLOWED_HOSTS:
        return False, "forbidden host"
    if headers.get("Origin"):
        return False, "origin header is not allowed"
    sent = str(headers.get(TOKEN_HEADER) or "")
    if require_token:
        if not sent or not token or not hmac.compare_digest(sent, token):
            return False, "invalid token"
    elif sent and (not token or not hmac.compare_digest(sent, token)):
        return False, "invalid token"
    return True, ""


def write_api_state(token):
    """Publish port/token for the local MCP bridge; never log the token."""
    try:
        from appcore import APP_DIR
    except Exception:
        return None
    path = os.path.join(APP_DIR, "agent_api.json")
    temp_path = path + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump({"host": API_HOST, "port": API_PORT,
                       "token_header": TOKEN_HEADER, "token": token}, handle)
        os.replace(temp_path, path)
        return path
    except OSError:
        return None


class _Adapter(QObject):
    """Слоты для исполнения в GUI-потоке."""

    def __init__(self, window):
        super().__init__()
        self.window = window

    def _servers_snapshot(self):
        w = self.window
        servers = list(getattr(w, "_servers", None) or [])
        if not servers:
            try:
                servers, _sub = w._collect_servers_for_start()
            except Exception:
                servers = []
        return servers

    @Slot(str, result=bool)
    def connectServer(self, name):
        """Найти сервер по хосту/remark/ключу и подключить. False = не найден/занято."""
        w = self.window
        from builder import server_key, server_address  # лёгкий импорт без GUI-стороны
        needle = str(name or "").strip().casefold()
        if not needle:
            return False
        for i, srv in enumerate(self._servers_snapshot()):
            keys = {
                str(server_key(srv) or "").casefold(),
                str(server_address(srv) or "").casefold(),
                str(srv.get("remark") or "").casefold(),
            }
            if any(needle == k or needle in k for k in keys if k):
                w.connect_server(srv, i)
                return True
        return False

    @Slot(result=bool)
    def disconnectVpn(self):
        self.window.stop_vpn()
        return True

    @Slot(result=bool)
    def startAiMode(self):
        w = self.window
        w.current_mode = "auto"
        w._run_vpn_worker(w.smart_start_auto)
        return True

    @Slot(bool, result=bool)
    def setWarp(self, enabled):
        self.window.set_warp_enabled(bool(enabled))
        return True

    @Slot(result=str)
    def serversJson(self):
        from builder import server_key, server_address, server_port
        out = []
        for i, srv in enumerate(self._servers_snapshot()):
            out.append({
                "index": i,
                "key": server_key(srv),
                "host": server_address(srv),
                "port": server_port(srv),
                "remark": str(srv.get("remark") or "")[:60],
            })
        return json.dumps(out, ensure_ascii=False)


class AgentAPI(threading.Thread):
    """HTTP-поток control-API. Падение API не должно валить приложение."""

    def __init__(self, window):
        super().__init__(daemon=True, name="AgentAPI")
        self.adapter = _Adapter(window)
        self._srv = None
        self.token = secrets.token_hex(16)
        self.require_token = str(
            os.environ.get(REQUIRE_TOKEN_ENV) or ""
        ).strip().lower() in ("1", "true", "yes", "on")

    def run(self):
        adapter = self.adapter
        token = self.token
        require_token = self.require_token
        write_api_state(token)

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, payload):
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self):
                allowed, reason = is_authorized(
                    self.headers, token, require_token=require_token
                )
                if not allowed:
                    self._send(403, {"error": reason})
                return allowed

            def _read_body(self):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except (TypeError, ValueError):
                    length = 0
                if length <= 0 or length > 65536:
                    return {}
                try:
                    return json.loads(self.rfile.read(length).decode("utf-8"))
                except Exception:
                    return {}

            def do_GET(self):
                if not self._authorized():
                    return
                path = self.path.split("?", 1)[0]
                w = adapter.window
                try:
                    if path == "/status":
                        self._send(200, {
                            "app": "GibVPN",
                            "vpn_running": bool(getattr(w, "is_running", False)),
                            "connected_at": getattr(w, "_connected_at", None),
                            "mode": getattr(w, "current_mode", None),
                            "warp_enabled": bool(getattr(w, "warp_enabled", False)),
                            "tun": bool(getattr(w, "use_tun", False)),
                            "manual_server": getattr(w, "manual_server", None),
                            "active_server": getattr(w, "_active_server", None),
                            "active_server_key_index": getattr(w, "_active_server_index", None),
                            "ai_last_servers": getattr(w, "ai_last_servers", {}) or {},
                            "workers_busy": bool(getattr(w, "_worker", None) and w._worker.isRunning()),
                        })
                    elif path == "/servers":
                        result = QMetaObject.invokeMethod(
                            adapter, "serversJson", Qt.ConnectionType.BlockingQueuedConnection,
                            Q_RETURN_ARG(str),
                        )
                        self._send(200, {"servers": json.loads(result or "[]")})
                    else:
                        self._send(404, {"error": "unknown path"})
                except Exception as e:
                    self._send(500, {"error": str(e)[:200]})

            def do_POST(self):
                if not self._authorized():
                    return
                path = self.path.split("?", 1)[0]
                try:
                    body = self._read_body()
                    if path == "/connect":
                        name = str(body.get("server") or "")
                        ok = QMetaObject.invokeMethod(
                            adapter, "connectServer", Qt.ConnectionType.BlockingQueuedConnection,
                            Q_RETURN_ARG(bool), Q_ARG(str, name),
                        )
                        self._send(200 if ok else 400, {
                            "ok": bool(ok),
                            "detail": "" if ok else f"сервер '{name}' не найден или агент занят",
                        })
                    elif path == "/disconnect":
                        ok = QMetaObject.invokeMethod(
                            adapter, "disconnectVpn", Qt.ConnectionType.BlockingQueuedConnection,
                            Q_RETURN_ARG(bool),
                        )
                        self._send(200, {"ok": bool(ok)})
                    elif path == "/mode/ai":
                        ok = QMetaObject.invokeMethod(
                            adapter, "startAiMode", Qt.ConnectionType.BlockingQueuedConnection,
                            Q_RETURN_ARG(bool),
                        )
                        self._send(200, {"ok": bool(ok), "detail": "запущен подбор «ИИ»"})
                    elif path == "/warp":
                        ok = QMetaObject.invokeMethod(
                            adapter, "setWarp", Qt.ConnectionType.BlockingQueuedConnection,
                            Q_RETURN_ARG(bool), Q_ARG(bool, bool(body.get("enabled"))),
                        )
                        self._send(200, {"ok": bool(ok), "warp_enabled": bool(body.get("enabled"))})
                    else:
                        self._send(404, {"error": "unknown path"})
                except Exception as e:
                    self._send(500, {"error": str(e)[:200]})

            def log_message(self, fmt, *args):  # тишина в консоль приложения
                pass

        try:
            self._srv = ThreadingHTTPServer((API_HOST, API_PORT), Handler)
            self._srv.serve_forever(poll_interval=0.5)
        except Exception as e:
            try:
                from appcore import write_session_log
                write_session_log(
                    f"[AgentAPI] не запустился на {API_HOST}:{API_PORT}: {e}"
                )
            except Exception:
                pass

    def stop(self):
        if self._srv:
            self._srv.shutdown()
