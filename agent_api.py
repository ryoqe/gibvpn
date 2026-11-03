# -*- coding: utf-8 -*-
"""Локальный control-API GibVPN для ИИ-агента (мост gibvpn-mcp).

Слушает ТОЛЬКО 127.0.0.1:7781. Эндпоинты:
  GET  /status                 — состояние окна/VPN (чтение атрибутов, без Qt-вызовов)
  GET  /servers                — список серверов активной подписки (в GUI-потоке)
  POST /connect  {"server": X} — подключить сервер по имени/хосту/remark
  POST /disconnect             — stop_vpn()
  POST /mode/ai                — штатный подбор «ИИ» (smart_start_auto)
  POST /warp     {"enabled":B} — set_warp_enabled(B)

Ответ всегда application/json. HTTP-поток никогда не трогает Qt напрямую:
действия исполняются в GUI-потоке через BlockingQueuedConnection.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from PyQt6.QtCore import (QObject, pyqtSlot as Slot, QMetaObject, Q_ARG,
                          Q_RETURN_ARG, Qt)

API_PORT = 7781
API_HOST = "127.0.0.1"


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

    def run(self):
        adapter = self.adapter

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, payload):
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
            print(f"[AgentAPI] не запустился: {e}")

    def stop(self):
        if self._srv:
            self._srv.shutdown()
