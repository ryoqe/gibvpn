import sys
import os
import subprocess
import threading
import requests
import time
import json
import shutil
import winreg
from concurrent.futures import ThreadPoolExecutor

import builder
import appcore
from appcore import (
    APP_DIR, WORK_DIR, LOG_PATH,
    log_exception, terminate_process,
    find_default_zapret_dir, start_zapret_process, stop_zapret_process,
)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout,
    QHBoxLayout, QLabel, QPlainTextEdit, QFrame, QFileDialog,
    QMessageBox, QDialog, QSystemTrayIcon, QMenu, QComboBox,
    QLineEdit
)
from PyQt6.QtGui import QPainter, QColor, QFont, QPixmap, QPalette, QIcon, QShortcut, QKeySequence, QFontDatabase
from PyQt6.QtCore import Qt, pyqtSignal, QLockFile, QTimer

from widgets import Worker, GearButton
from dialogs import (
    ZapretTestThread, SettingsDialog, PingSitesDialog,
    SubscriptionEditDialog, SubscriptionManagerDialog,
    _PingItem, _ping_color, ServerListDialog
)


class GibVPNApp(QMainWindow):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str, str)
    toggle_signal = pyqtSignal(str, str, str, bool)
    show_dialog_signal = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("GibVPN - Smart Core")
        self.resize(1120, 680)
        self.setMinimumSize(940, 560)

        self.is_running = False
        self.xray_process = None
        self._xray_processes = set()
        self.current_mode = "min"
        self._traffic_up = 0
        self._traffic_down = 0
        self._traffic_up_speed = 0.0
        self._traffic_down_speed = 0.0
        self._traffic_last = None
        self._traffic_thread = None

        self._connected_at = None
        self._conn_name = None
        self._conn_ping_ms = 0
        self._background_thread = None
        self._reconnect_in_progress = False
        self._watcher_thread = None
        self._tray = None
        self._tray_notified = False
        self._force_quit = False
        self._test_port_offset = 0
        self.custom_links = []

        self.check_sites = {
            "Google": "http://www.google.com/generate_204",
            "Cloudflare": "http://cp.cloudflare.com/generate_204",
            "GStatic": "http://connectivitycheck.gstatic.com/generate_204",
            "Telegram": "https://t.me",
            "Yandex": "http://ya.ru"
        }
        self.proxy_dict = {
            "http": "http://127.0.0.1:10809",
            "https": "http://127.0.0.1:10809"
        }

        self.subscriptions = []
        self.active_subscription_index = 0
        self.autostart_enabled = False
        self.auto_reconnect = False
        self.sub_auto_update_hours = 24
        self._sub_update_running = False

        self.ping_timeout = 5.0
        self.ping_attempts = 3

        self.use_zapret = False
        self.zapret_dir = find_default_zapret_dir()
        self.zapret_preset = "general.bat"
        self.zapret_process = None
        self.block_quic = True

        self.overlay_color = QColor(173, 216, 230, 120)
        self.bottom_image_path = None
        self.top_image_path = None
        self.bottom_crop = 0
        self.top_crop = 0
        self.bottom_offset_x = 0
        self.bottom_offset_y = 0
        self.top_offset_x = 0
        self.top_offset_y = 0
        self.warp_file = os.path.join(WORK_DIR, "warp_domains.txt")
        self.exc_file = os.path.join(WORK_DIR, "direct_domains.txt")
        self.apps_file = os.path.join(WORK_DIR, "direct_apps.txt")

        self.central = QWidget(self)
        self.setCentralWidget(self.central)

        self.setup_ui()
        self._set_cyrillic_font()

        self._log_lines = []

        self.log_signal.connect(self._log_slot)
        self.status_signal.connect(self._status_slot)
        self.toggle_signal.connect(self._toggle_slot)
        self.show_dialog_signal.connect(self._show_dialog_slot)

        self.load_settings()
        self._setup_tray()
        self._setup_hotkeys()

        self._uptime_timer = QTimer(self)
        self._uptime_timer.timeout.connect(self._tick_uptime)
        self._uptime_timer.start(30000)

        self._sub_timer = QTimer(self)
        self._sub_timer.timeout.connect(self._maybe_auto_update_sub)
        self._sub_timer.start(15 * 60 * 1000)

        self.log(f"Application started. Work dir: {WORK_DIR}")
        if not os.path.exists("xray.exe"):
            self.log("WARNING: xray.exe not found in work dir!")

    def setup_ui(self):
        margin = 16
        gap = 10
        small_btn_h = 44
        big_btn_size = 74
        gear_size = 46

        self.left_panel = QWidget(self.central)
        self.left_panel.setStyleSheet("background-color: transparent;")
        self.left_layout = QVBoxLayout(self.left_panel)
        self.left_layout.setContentsMargins(0, 0, 0, 0)
        self.left_layout.setSpacing(gap)
        self.left_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        self.btn_settings = GearButton(self.left_panel)
        self.btn_settings.setFixedSize(gear_size, gear_size)
        self.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_settings.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(255, 255, 255, 210);
                border: none;
                border-radius: {gear_size // 2}px;
                color: #333;
                text-align: center;
                padding: 0;
            }}
            QPushButton:hover {{ background-color: white; }}
            QPushButton:pressed {{ background-color: #e0e0e0; }}
        """)
        self.btn_settings.setToolTip("Настройки")
        self.btn_settings.clicked.connect(self.open_settings)
        self.left_layout.addWidget(self.btn_settings)

        left_btn_style = """
            QPushButton {
                font-size: 12px;
                color: #F8FAFC;
                background-color: rgba(255, 255, 255, 20);
                border: 1px solid rgba(255, 255, 255, 40);
                border-radius: 10px;
                padding: 7px 10px;
                text-align: left;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 55);
                color: #38BDF8;
                border-color: rgba(56, 189, 248, 140);
            }
            QPushButton:pressed {
                background-color: rgba(255, 255, 255, 80);
            }
        """

        self.btn_servers_dlg = QPushButton("📋 Список серверов...", self.left_panel)
        self.btn_servers_dlg.setStyleSheet(left_btn_style)
        self.btn_servers_dlg.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_servers_dlg.setToolTip("Открыть список всех серверов подписки (избранное, пинг, выбор)")
        self.btn_servers_dlg.clicked.connect(self.open_servers_dialog)
        self.left_layout.addWidget(self.btn_servers_dlg)

        self.btn_ping_sites_dlg = QPushButton("🌐 Сайты для пинга...", self.left_panel)
        self.btn_ping_sites_dlg.setStyleSheet(left_btn_style)
        self.btn_ping_sites_dlg.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ping_sites_dlg.setToolTip("Настроить список сайтов для проверки доступности в режиме МАКС")
        self.btn_ping_sites_dlg.clicked.connect(self.open_ping_sites_dialog)
        self.left_layout.addWidget(self.btn_ping_sites_dlg)

        self.warp_link = QPushButton("🚀 WARP домены", self.left_panel)
        self.warp_link.setStyleSheet(left_btn_style)
        self.warp_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.warp_link.setToolTip("Список сайтов, идущих через туннель Cloudflare WARP")
        self.warp_link.clicked.connect(lambda: self.open_text_file("#warp"))
        self.left_layout.addWidget(self.warp_link)

        self.exc_link = QPushButton("⚡ Исключения (домены)", self.left_panel)
        self.exc_link.setStyleSheet(left_btn_style)
        self.exc_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.exc_link.setToolTip("Сайты, идущие напрямую (в обход VPN)")
        self.exc_link.clicked.connect(lambda: self.open_text_file("#exc"))
        self.left_layout.addWidget(self.exc_link)

        self.apps_link = QPushButton("📱 Исключения (приложения)", self.left_panel)
        self.apps_link.setStyleSheet(left_btn_style)
        self.apps_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.apps_link.setToolTip("Приложения Windows, идущие напрямую в обход VPN (direct_apps.txt)")
        self.apps_link.clicked.connect(lambda: self.open_text_file("#apps"))
        self.left_layout.addWidget(self.apps_link)

        self.xray_cfg_link = QPushButton("🛠 Конфиг Xray", self.left_panel)
        self.xray_cfg_link.setStyleSheet(left_btn_style)
        self.xray_cfg_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.xray_cfg_link.setToolTip("Просмотр и редактирование итогового файла config.json")
        self.xray_cfg_link.clicked.connect(lambda: self.open_text_file("#xray"))
        self.left_layout.addWidget(self.xray_cfg_link)

        self.logs_panel = QWidget(self.central)
        self.logs_panel.setObjectName("logs_panel")
        self.logs_panel.setStyleSheet("""
            QWidget#logs_panel {
                background-color: rgba(15, 23, 42, 145);
                border: 1px solid rgba(255, 255, 255, 40);
                border-radius: 14px;
            }
        """)
        logs_layout = QVBoxLayout(self.logs_panel)
        logs_layout.setContentsMargins(10, 10, 10, 10)
        logs_layout.setSpacing(6)

        log_filter = QHBoxLayout()
        log_filter.setContentsMargins(0, 0, 0, 0)
        log_filter.setSpacing(6)
        log_input_style = (
            "background-color: rgba(255, 255, 255, 30);"
            "color: #FFFFFF; border: 1px solid rgba(255, 255, 255, 45);"
            "border-radius: 8px; padding: 4px 8px; font-size: 12px;"
        )
        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Поиск в логе...")
        self.log_search.setClearButtonEnabled(True)
        self.log_search.setStyleSheet(f"QLineEdit {{ {log_input_style} }}")
        self.log_search.textChanged.connect(self._refresh_log_view)
        log_filter.addWidget(self.log_search, 1)

        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["Все", "INFO+", "WARN+", "ERROR"])
        self.log_level_combo.setStyleSheet(
            f"QComboBox {{ {log_input_style} }}"
            "QComboBox QAbstractItemView { background-color: #0F172A; color: #FFFFFF; selection-background-color: #38BDF8; }"
        )
        self.log_level_combo.currentIndexChanged.connect(self._refresh_log_view)
        log_filter.addWidget(self.log_level_combo)
        logs_layout.addLayout(log_filter)

        log_tools = QHBoxLayout()
        log_tools.setContentsMargins(0, 0, 0, 0)
        log_tools.setSpacing(8)
        log_tool_style = """
            QPushButton {
                background-color: rgba(255, 255, 255, 30);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 45);
                border-radius: 10px;
                padding: 4px 12px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 60);
                color: #38BDF8;
            }
        """
        self.btn_copy_log = QPushButton("Копировать")
        self.btn_copy_log.setStyleSheet(log_tool_style)
        self.btn_copy_log.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_copy_log.setToolTip("Скопировать весь лог в буфер обмена")
        self.btn_copy_log.clicked.connect(self.copy_log)
        log_tools.addWidget(self.btn_copy_log)

        self.btn_clear_log = QPushButton("Очистить")
        self.btn_clear_log.setStyleSheet(log_tool_style)
        self.btn_clear_log.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear_log.setToolTip("Очистить окно логов")
        self.btn_clear_log.clicked.connect(self.clear_log)
        log_tools.addWidget(self.btn_clear_log)
        log_tools.addStretch()
        logs_layout.addLayout(log_tools)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet(
            "QPlainTextEdit {"
            "  background-color: transparent; border: none;"
            "  font-size: 11px; color: #F1F5F9;"
            "}"
        )
        logs_layout.addWidget(self.log_box)

        self.status_frame = QFrame(self.central)
        self.status_frame.setFrameShape(QFrame.Shape.NoFrame)
        self.status_frame.setStyleSheet("background-color: transparent;")
        status_layout = QVBoxLayout(self.status_frame)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(6)

        self.status_title = QLabel("СТАТУС")
        self.status_title.setStyleSheet(
            "color: #D8D8DE; font-size: 12px; font-weight: bold; letter-spacing: 1px;"
            "background-color: rgba(0,0,0,110); border-radius: 10px; padding: 4px 10px;"
        )
        self.status_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self.status_title)

        self.status_value = QLabel("STOPPED")
        self.status_value.setStyleSheet(
            "color: #B8B8C0; font-size: 12px; font-weight: bold;"
            "background-color: rgba(0,0,0,110); border-radius: 10px; padding: 6px 10px;"
        )
        self.status_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_value.setWordWrap(True)
        status_layout.addWidget(self.status_value)

        toggle_w = 288
        toggle_h = 38
        self.btn_toggle = QPushButton("СТАРТ", self.central)
        self.btn_toggle.setGeometry((self.width() - toggle_w) // 2, margin + 4, toggle_w, toggle_h)
        self.btn_toggle.setStyleSheet(self._pill_btn_style("#42A5F5"))
        self.btn_toggle.setToolTip("Запустить/остановить VPN")
        self.btn_toggle.clicked.connect(self.toggle_vpn)
        big_btn_size = 84
        small_btn_h = 48
        group_gap = 45

        self.bottom_panel = QWidget(self.central)
        self.bottom_panel.setStyleSheet("background-color: transparent;")
        self.bottom_layout = QHBoxLayout(self.bottom_panel)
        self.bottom_layout.setContentsMargins(0, 0, 0, 0)
        self.bottom_layout.setSpacing(14)

        self.btn_min = QPushButton("МИН", self.bottom_panel)
        self.btn_min.setFixedSize(big_btn_size, big_btn_size)
        self.btn_min.setStyleSheet(self._round_btn_style(selected=True))
        self.btn_min.setToolTip("Выбрать сервер с самым быстрым пингом")
        self.btn_min.clicked.connect(self.on_min_clicked)

        self.btn_max = QPushButton("МАКС", self.bottom_panel)
        self.btn_max.setFixedSize(big_btn_size, big_btn_size)
        self.btn_max.setStyleSheet(self._round_btn_style(selected=False))
        self.btn_max.setToolTip("Выбрать сервер с максимальной доступностью сайтов")
        self.btn_max.clicked.connect(self.on_max_clicked)

        self.btn_ping = QPushButton("Пинг", self.bottom_panel)
        self.btn_ping.setFixedSize(110, small_btn_h)
        self.btn_ping.setStyleSheet(self._pill_btn_style())
        self.btn_ping.setToolTip("Проверить пинг до выбранных сервисов")
        self.btn_ping.clicked.connect(self.on_ping_clicked)

        self.bottom_layout.addWidget(self.btn_min)
        self.bottom_layout.addWidget(self.btn_max)
        self.bottom_layout.addSpacing(group_gap)
        self.bottom_layout.addWidget(self.btn_ping)
        self.bottom_layout.addStretch(1)

        self._update_mode_buttons()

    def _set_cyrillic_font(self):
        chosen = ""
        candidates = []
        fonts_dir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")
        for name in ("segoeui.ttf", "tahoma.ttf", "arial.ttf"):
            candidates.append(os.path.join(fonts_dir, name))
        for folder in (
            os.path.join(WORK_DIR, "assets"), WORK_DIR,
            os.path.join(APP_DIR, "assets"), APP_DIR,
        ):
            try:
                candidates.extend(
                    os.path.join(folder, f) for f in os.listdir(folder)
                    if f.lower().endswith((".ttf", ".otf"))
                )
            except Exception:
                pass
        for path in candidates:
            if not os.path.exists(path):
                continue
            fid = QFontDatabase.addApplicationFont(path)
            if fid != -1:
                fams = QFontDatabase.applicationFontFamilies(fid)
                if fams:
                    chosen = fams[0]
                    break
        font = QFont(chosen if chosen else "Segoe UI", 10)
        self.setFont(font)

    def log(self, message):
        self.log_signal.emit(str(message))

    def _log_slot(self, message):
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        level = self._log_level(message)
        self._log_lines.append((level, line))
        if len(self._log_lines) > 5000:
            del self._log_lines[:2500]
        if self._log_passes(level, line):
            self.log_box.appendPlainText(line)

    @staticmethod
    def _log_level(message):
        m = message.upper()
        if "CRITICAL" in m or "ERROR" in m or "FAIL" in m:
            return 3
        if "WARN" in m:
            return 2
        return 1

    def _log_passes(self, level, line):
        if level < self.log_level_combo.currentIndex():
            return False
        needle = self.log_search.text().strip().lower()
        return not needle or needle in line.lower()

    def _refresh_log_view(self):
        self.log_box.setPlainText("\n".join(
            line for level, line in self._log_lines if self._log_passes(level, line)
        ))
        bar = self.log_box.verticalScrollBar()
        bar.setValue(bar.maximum())

    def copy_log(self):
        text = self.log_box.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.log("Лог скопирован в буфер обмена")

    def clear_log(self):
        self.log_box.clear()
        self._log_lines.clear()
        self.log("Лог очищен")

    def set_status(self, text, color):
        self.status_signal.emit(text, color)

    _STATUS_PALETTE = {
        "green": "#7CD4FC",
        "orange": "#FFB340",
        "red": "#FF6B62",
        "gray": "#B8B8C0",
        "yellow": "#FFE066",
    }

    def _status_slot(self, text, color):
        hex_color = self._STATUS_PALETTE.get(color, color)
        self.status_value.setText(text)
        self.status_value.setStyleSheet(
            f"color: {hex_color}; font-size: 12px; font-weight: bold;"
            f"background-color: rgba(0,0,0,110); border-radius: 10px; padding: 6px 10px;"
        )

    def set_toggle(self, text, fg, hover, enabled):
        self.toggle_signal.emit(text, fg, hover, enabled)

    @staticmethod
    def _contrast_text(bg_hex):
        c = QColor(bg_hex)
        if not c.isValid():
            return "white"
        lum = 0.299 * c.red() + 0.587 * c.green() + 0.114 * c.blue()
        return "#102A43" if lum > 140 else "white"

    def _toggle_slot(self, text, fg, hover, enabled):
        self.btn_toggle.setText(text)
        fg_text = self._contrast_text(fg)
        self.btn_toggle.setStyleSheet(f"""
            QPushButton {{
                background-color: {fg};
                border: none;
                border-radius: 14px;
                font-size: 14px;
                font-weight: bold;
                color: {fg_text};
                text-align: center;
                padding: 0;
            }}
            QPushButton:hover {{ background-color: {hover}; }}
            QPushButton:disabled {{ background-color: rgba(120,120,120,150); color: white; }}
        """)
        self.btn_toggle.setEnabled(enabled)

    def _show_dialog_slot(self, kind, title, text):
        if kind == "critical":
            QMessageBox.critical(self, title, text)
        elif kind == "warning":
            QMessageBox.warning(self, title, text)
        else:
            QMessageBox.information(self, title, text)

    def _update_mode_buttons(self):
        self.btn_min.setStyleSheet(self._round_btn_style(selected=(self.current_mode == "min")))
        self.btn_max.setStyleSheet(self._round_btn_style(selected=(self.current_mode == "max")))

    def _start_current_mode(self):
        if self.current_mode == "max":
            self._run_vpn_worker(self.smart_start_max_availability)
        else:
            self._run_vpn_worker(self.smart_start_vpn)

    def on_min_clicked(self):
        self.current_mode = "min"
        self.save_settings()
        self._update_mode_buttons()
        self.log("Режим VPN: МИН (быстрый пинг)")
        if self.is_running:
            self.stop_vpn()
            self._start_current_mode()

    def on_max_clicked(self):
        self.current_mode = "max"
        self.save_settings()
        self._update_mode_buttons()
        self.log("Режим VPN: МАКС (максимальная доступность)")
        if self.is_running:
            self.stop_vpn()
            self._start_current_mode()

    def _run_vpn_worker(self, fn):
        self.set_toggle("СТОП", "#1F4E79", "#2A6299", False)
        self._worker = Worker(fn)
        self._worker.error.connect(lambda e: (self.log(f"CRITICAL ERROR: {e}"),
                                              self.set_status(f"Error: {e}", "red"),
                                              self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)))
        self._worker.start()

    def toggle_vpn(self):
        if not self.is_running:
            self.log("[UI] Запуск VPN...")
            self.set_toggle("ЗАПУСК...", "#FFA000", "#FFB300", False)
            self._start_current_mode()
        else:
            self.log("[UI] Остановка VPN...")
            self.is_running = False
            self.stop_vpn()

    def closeEvent(self, event):
        self.save_settings()
        if not self._force_quit and self._tray is not None:
            event.ignore()
            self.hide()
            if not self._tray_notified:
                self._tray_notified = True
                self._tray.showMessage(
                    "GibVPN",
                    "Приложение свёрнуто в трей. Для выхода используйте меню иконки.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )
            return
        self.is_running = False
        self.stop_vpn()
        event.accept()

    def _make_tray_icon(self):
        pix = QPixmap(64, 64)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#007AFF"))
        painter.drawEllipse(4, 4, 56, 56)
        painter.setPen(QColor("white"))
        painter.setFont(QFont(self.font().family(), 26, QFont.Weight.Bold))
        painter.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, "G")
        painter.end()
        return QIcon(pix)

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self._tray = QSystemTrayIcon(self._make_tray_icon(), self)
        self._tray.setToolTip("GibVPN - Smart Core")

        menu = QMenu()
        act_show = menu.addAction("Показать")
        act_show.triggered.connect(self._tray_show_window)
        act_toggle = menu.addAction("Старт / Стоп")
        act_toggle.triggered.connect(self.toggle_vpn)
        menu.addSeparator()
        act_quit = menu.addAction("Выход")
        act_quit.triggered.connect(self._quit_from_tray)
        self._tray.setContextMenu(menu)

        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _tray_show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self._tray_show_window()

    def _quit_from_tray(self):
        self._force_quit = True
        self.close()

    def _setup_hotkeys(self):
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self.update_active_subscription_bg)
        QShortcut(QKeySequence("Ctrl+S"), self, activated=self.open_settings)
        QShortcut(QKeySequence(Qt.Key.Key_Space), self, activated=self.toggle_vpn)

    def update_active_subscription_bg(self):
        sub = self._active_subscription()
        if not sub or not sub.get("url"):
            self.log("Нет активной подписки с URL для обновления")
            return
        if self._sub_update_running:
            self.log("Обновление подписки уже выполняется...")
            return
        self._sub_update_running = True
        self.log(f"Обновление подписки «{sub.get('name', 'Без имени')}»...")

        def work():
            try:
                self.update_subscription(sub["url"], sub)
            finally:
                self._sub_update_running = False

        threading.Thread(target=work, daemon=True).start()

    def _maybe_auto_update_sub(self):
        if not self.sub_auto_update_hours:
            return
        sub = self._active_subscription()
        if not sub or not sub.get("url"):
            return
        last = sub.get("updated_at", 0)
        if time.time() - last < self.sub_auto_update_hours * 3600:
            return
        self.log(f"[AUTO] Подписка устарела (>{self.sub_auto_update_hours}ч), обновляю...")
        self.update_active_subscription_bg()

    def _running_status_text(self):
        name = self._conn_name or "?"
        if 0 < self._conn_ping_ms < 5000:
            ping_str = f"{self._conn_ping_ms}ms"
        elif self._conn_ping_ms == 0:
            ping_str = "<10ms"
        else:
            ping_str = ">5s"
        parts = [f"RUNNING • {name} • {ping_str}"]
        if self._connected_at:
            secs = int(time.time() - self._connected_at)
            hours, rem = divmod(secs, 3600)
            mins, s = divmod(rem, 60)
            up = f"{hours}ч {mins:02d}м" if hours else f"{mins}м {s:02d}с"
            parts.append(up)
        if self._traffic_up or self._traffic_down:
            down = self._fmt_bytes(self._traffic_down).replace(" ", "")
            up_b = self._fmt_bytes(self._traffic_up).replace(" ", "")
            parts.append(f"↓{down} ↑{up_b}")
            if self._traffic_down_speed or self._traffic_up_speed:
                ds = self._fmt_bytes(self._traffic_down_speed).replace(" ", "")
                us = self._fmt_bytes(self._traffic_up_speed).replace(" ", "")
                parts.append(f"↓{ds}/s ↑{us}/s")
        return " • ".join(parts)

    def _tick_uptime(self):
        if self.is_running and self._connected_at:
            self.set_status(self._running_status_text(), "green")

    def _spawn_xray(self, is_test=False):
        xray_exe = os.path.join(WORK_DIR, "xray.exe")
        if not os.path.exists(xray_exe):
            xray_exe = "xray.exe"
        config_path = os.path.join(WORK_DIR, "config.json")
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.Popen(
            [xray_exe, "run", "-c", config_path],
            cwd=WORK_DIR,
            startupinfo=startupinfo
        )
        if is_test:
            self._xray_processes.add(proc)
        return proc

    def _reap_xray(self, proc):
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=0.5)
            except Exception:
                pass
            self._xray_processes.discard(proc)

    def kill_orphaned_xray(self):
        for proc in list(self._xray_processes):
            if proc != self.xray_process:
                try:
                    proc.kill()
                    proc.wait(timeout=0.5)
                except Exception:
                    pass
                self._xray_processes.discard(proc)

    def smart_start_vpn(self):
        try:
            self._reconnect_in_progress = True
            self._smart_start_vpn_inner()
        except Exception as e:
            log_exception("smart_start_vpn crashed")
            self.set_status(f"Error: {e}", "red")
            self.log(f"CRITICAL ERROR: {e}")
            self.log(f"Details saved to {LOG_PATH}")
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
        finally:
            self._reconnect_in_progress = False

    def _smart_start_vpn_inner(self):
        self.set_status("PARSING SERVERS...", "orange")

        xray_exe = os.path.join(WORK_DIR, "xray.exe")
        if not os.path.exists(xray_exe) and not shutil.which("xray.exe"):
            self.set_status("Error: xray.exe not found", "red")
            self.log(f"ERROR: xray.exe не найден в {WORK_DIR}!")
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
            self.show_dialog_signal.emit(
                "critical", "Ошибка запуска",
                f"Файл xray.exe не найден в папке программы:\n{WORK_DIR}\n\nПожалуйста, убедитесь, что xray.exe расположен рядом с приложением."
            )
            return

        servers, sub = self._collect_servers_for_start()
        if servers is None:
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
            self.show_dialog_signal.emit(
                "warning", "Нет доступных серверов",
                "У вас пока не добавлено ни одной подписки и нет своих серверов!\n\n"
                "Пожалуйста, нажмите «Список серверов...» или «Настройки» и добавьте URL подписки или VLESS/VMESS ссылку."
            )
            return
        self._servers = servers

        favorites, regular, blocked = self._filter_servers(servers, sub)
        self.log(f"[CORE] Subscription '{sub.get('name') if sub else 'свои серверы'}': {len(servers)} servers, {len(favorites)} favorite, {len(regular)} regular, {len(blocked)} blocked")
        for i, srv in enumerate(servers[:5]):
            self.log(f"[CORE] Server {i}: {builder.server_key(srv)}")
        if len(servers) > 5:
            self.log(f"[CORE] ... and {len(servers) - 5} more servers")

        favorite_pairs = [(i, s) for i, s in enumerate(servers) if s in favorites]
        regular_pairs = [(i, s) for i, s in enumerate(servers) if s in regular]

        best_index = None
        best_server = None
        best_ping = 999.0
        source = "favorite"

        if favorite_pairs:
            self.set_status(f"TESTING {len(favorite_pairs)} FAVORITE SERVERS...", "orange")
            self.log(f"[CORE] Testing favorite servers first")
            fav_results = self._run_ping_test(favorite_pairs)
            if fav_results:
                fav_results.sort(key=lambda x: x[1])
                best_index, best_ping = fav_results[0]
                best_server = servers[best_index]
                self.log(f"[CORE] Best favorite server: #{best_index}, {int(best_ping * 1000)}ms")

        if best_server is None and regular_pairs:
            if favorite_pairs:
                self.log("[CORE] No favorite server responded, testing regular servers")
            self.set_status(f"TESTING {len(regular_pairs)} REGULAR SERVERS...", "orange")
            reg_results = self._run_ping_test(regular_pairs)
            if reg_results:
                reg_results.sort(key=lambda x: x[1])
                best_index, best_ping = reg_results[0]
                best_server = servers[best_index]
                source = "regular"
                self.log(f"[CORE] Best regular server: #{best_index}, {int(best_ping * 1000)}ms")

        if best_server is None:
            self.set_status("ALL SERVERS ARE DEAD!", "red")
            self.log("CRITICAL ERROR: All available servers failed the ping test.")
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
            return

        ping_ms = int(best_ping * 1000)
        self.set_status("GENERATING FINAL CONFIG...", "orange")
        self.log("[CORE] Generating final routing config...")
        self._start_best_server(best_server, best_index, ping_ms)

        if source == "favorite" and regular_pairs:
            self._start_background_regular_test(regular_pairs, best_ping, mode="min")

    def smart_start_max_availability(self):
        try:
            self._reconnect_in_progress = True
            self._smart_start_max_inner()
        except Exception as e:
            log_exception("smart_start_max_availability crashed")
            self.set_status(f"Error: {e}", "red")
            self.log(f"CRITICAL ERROR: {e}")
            self.log(f"Details saved to {LOG_PATH}")
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
        finally:
            self._reconnect_in_progress = False

    def _smart_start_max_inner(self):
        self.set_status("PARSING SERVERS...", "orange")

        xray_exe = os.path.join(WORK_DIR, "xray.exe")
        if not os.path.exists(xray_exe) and not shutil.which("xray.exe"):
            self.set_status("Error: xray.exe not found", "red")
            self.log(f"ERROR: xray.exe не найден в {WORK_DIR}!")
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
            self.show_dialog_signal.emit(
                "critical", "Ошибка запуска",
                f"Файл xray.exe не найден в папке программы:\n{WORK_DIR}\n\nПожалуйста, убедитесь, что xray.exe расположен рядом с приложением."
            )
            return

        servers, sub = self._collect_servers_for_start()
        if servers is None:
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
            self.show_dialog_signal.emit(
                "warning", "Нет доступных серверов",
                "У вас пока не добавлено ни одной подписки и нет своих серверов!\n\n"
                "Пожалуйста, нажмите «Список серверов...» или «Настройки» и добавьте URL подписки или VLESS/VMESS ссылку."
            )
            return
        self._servers = servers

        favorites, regular, blocked = self._filter_servers(servers, sub)
        self.log(f"[CORE] Subscription '{sub.get('name') if sub else 'свои серверы'}': {len(servers)} servers, {len(favorites)} favorite, {len(regular)} regular, {len(blocked)} blocked")
        sites = ", ".join(self.check_sites.keys())
        self.log(f"[CORE] Target sites: {sites}")

        favorite_pairs = [(i, s) for i, s in enumerate(servers) if s in favorites]
        regular_pairs = [(i, s) for i, s in enumerate(servers) if s in regular]

        best_index = None
        best_server = None
        best_metric = (0, 999.0)
        source = "favorite"

        if favorite_pairs:
            self.set_status(f"TESTING {len(favorite_pairs)} FAVORITE SERVERS...", "orange")
            self.log(f"[CORE] Testing favorite servers first")
            fav_results = self._run_availability_test(favorite_pairs)
            if fav_results:
                fav_results.sort(key=lambda x: (-x[1], x[2]))
                best_index, best_count, best_ping = fav_results[0]
                best_server = servers[best_index]
                best_metric = (best_count, best_ping)
                self.log(f"[CORE] Best favorite server: #{best_index}, {best_count}/{len(self.check_sites)} sites, avg {int(best_ping * 1000)}ms")

        if best_server is None and regular_pairs:
            if favorite_pairs:
                self.log("[CORE] No favorite server responded, testing regular servers")
            self.set_status(f"TESTING {len(regular_pairs)} REGULAR SERVERS...", "orange")
            reg_results = self._run_availability_test(regular_pairs)
            if reg_results:
                reg_results.sort(key=lambda x: (-x[1], x[2]))
                best_index, best_count, best_ping = reg_results[0]
                best_server = servers[best_index]
                best_metric = (best_count, best_ping)
                source = "regular"
                self.log(f"[CORE] Best regular server: #{best_index}, {best_count}/{len(self.check_sites)} sites, avg {int(best_ping * 1000)}ms")

        if best_server is None:
            self.set_status("ALL SERVERS ARE DEAD!", "red")
            self.log("CRITICAL ERROR: All available servers failed availability test.")
            self.is_running = False
            self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)
            return

        ping_ms = int(best_metric[1] * 1000)
        self.set_status("GENERATING FINAL CONFIG...", "orange")
        self.log("[CORE] Generating final routing config...")
        self._start_best_server(best_server, best_index, ping_ms)

        if source == "favorite" and regular_pairs:
            self._start_background_regular_test(regular_pairs, best_metric, mode="max")

    def ping_test_proxy(self, port, result_list, index):
        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}"
        }
        test_urls = [
            "https://www.google.com/generate_204",
            "http://www.google.com/generate_204",
            "http://cp.cloudflare.com/generate_204",
            "http://connectivitycheck.gstatic.com/generate_204"
        ]
        s = requests.Session()
        s.trust_env = False
        for url in test_urls:
            start = time.time()
            try:
                res = s.get(
                    url,
                    proxies=proxies,
                    timeout=(2.0, self.ping_timeout)
                )
                if res.status_code in (200, 204, 301, 302):
                    result_list.append((index, time.time() - start))
                    return
            except requests.exceptions.ConnectionError:
                time.sleep(0.1)
            except Exception:
                continue

    def availability_test_proxy(self, port, result_list, index):
        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}"
        }
        reachable = 0
        pings = []
        s = requests.Session()
        s.trust_env = False
        for name, url in self.check_sites.items():
            start = time.time()
            try:
                res = s.get(url, proxies=proxies, timeout=(2.0, 3.0))
                if res.status_code in (200, 204, 301, 302):
                    reachable += 1
                    pings.append(time.time() - start)
            except Exception:
                pass
        avg_ping = (sum(pings) / len(pings)) if pings else 999.0
        result_list.append((index, reachable, avg_ping))

    def _run_ping_test(self, servers_with_index, kill_existing=True):
        if not servers_with_index:
            return []
        test_servers = [srv for _, srv in servers_with_index]
        base_port = 11000 + (getattr(self, "_test_port_offset", 0) % 10) * 200
        self._test_port_offset = getattr(self, "_test_port_offset", 0) + 1
        builder.generate_test_config(test_servers, base_port=base_port)

        if kill_existing:
            self.kill_orphaned_xray()

        self.log(f"[CORE] Starting ping test for {len(test_servers)} servers (base_port={base_port})...")
        test_process = self._spawn_xray(is_test=True)
        results = []
        try:
            time.sleep(1.5)
            max_workers = min(20, max(1, len(servers_with_index)))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(self.ping_test_proxy, base_port + local_i, results, local_i)
                    for local_i, (orig_i, srv) in enumerate(servers_with_index)
                ]
                for f in futures:
                    try:
                        f.result(timeout=self.ping_timeout + 2)
                    except Exception:
                        pass
        finally:
            self._reap_xray(test_process)
        self.log("[CORE] Ping test xray terminated")

        mapped = []
        for local_i, ping in results:
            if local_i < len(servers_with_index):
                orig_i, _ = servers_with_index[local_i]
                mapped.append((orig_i, ping))
        return mapped

    def _run_availability_test(self, servers_with_index, kill_existing=True):
        if not servers_with_index:
            return []
        test_servers = [srv for _, srv in servers_with_index]
        base_port = 11000 + (getattr(self, "_test_port_offset", 0) % 10) * 200
        self._test_port_offset = getattr(self, "_test_port_offset", 0) + 1
        builder.generate_test_config(test_servers, base_port=base_port)

        if kill_existing:
            self.kill_orphaned_xray()

        self.log(f"[CORE] Starting availability test for {len(test_servers)} servers (base_port={base_port})...")
        test_process = self._spawn_xray(is_test=True)
        results = []
        try:
            time.sleep(1.5)
            max_workers = min(20, max(1, len(servers_with_index)))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(self.availability_test_proxy, base_port + local_i, results, local_i)
                    for local_i, (orig_i, srv) in enumerate(servers_with_index)
                ]
                for f in futures:
                    try:
                        f.result(timeout=12.0)
                    except Exception:
                        pass
        finally:
            self._reap_xray(test_process)
        self.log("[CORE] Availability test xray terminated")

        mapped = []
        for local_i, reachable, avg_ping in results:
            if local_i < len(servers_with_index):
                orig_i, _ = servers_with_index[local_i]
                mapped.append((orig_i, reachable, avg_ping))
        return mapped

    def _start_background_regular_test(self, regular_pairs, current_best_metric, mode):
        def worker():
            try:
                time.sleep(3.0)
                if not self.is_running or self._reconnect_in_progress:
                    return

                self.log(f"[CORE] Background testing {len(regular_pairs)} regular servers...")

                if mode == "min":
                    reg_results = self._run_ping_test(regular_pairs, kill_existing=False)
                    if not self.is_running or self._reconnect_in_progress:
                        return
                    if not reg_results:
                        self.log("[CORE] Background test: no regular servers responded")
                        return
                    reg_results.sort(key=lambda x: x[1])
                    best_idx, best_ping = reg_results[0]
                    self.log(f"[CORE] Background test finished: best regular server #{best_idx} ({int(best_ping * 1000)}ms). Retaining active Favorite server.")

                elif mode == "max":
                    reg_results = self._run_availability_test(regular_pairs, kill_existing=False)
                    if not self.is_running or self._reconnect_in_progress:
                        return
                    if not reg_results:
                        self.log("[CORE] Background test: no regular servers responded")
                        return
                    reg_results.sort(key=lambda x: (-x[1], x[2]))
                    best_idx, best_count, best_ping = reg_results[0]
                    self.log(f"[CORE] Background test finished: best regular server #{best_idx} ({best_count} sites). Retaining active Favorite server.")
            except Exception as e:
                log_exception("background regular test crashed")
                self.log(f"[CORE] Background test error: {e}")

        self._background_thread = threading.Thread(target=worker, daemon=True)
        self._background_thread.start()

    def _reconnect_to_better(self, server, index, ping_ms, source):
        if not self.is_running or self._reconnect_in_progress:
            return
        self._reconnect_in_progress = True
        try:
            self.log(f"[CORE] Better server found in {source}: #{index}, reconnecting...")
            self.set_status(f"SWITCHING TO #{index}...", "orange")
            self._start_best_server(server, index, ping_ms, start_watcher=False)
        finally:
            self._reconnect_in_progress = False

    def _start_best_server(self, best_server, best_index, ping_ms, start_watcher=True):
        use_zap = getattr(self, "use_zapret", False)
        builder.generate_final_config(best_server, use_zapret=use_zap, block_quic=getattr(self, "block_quic", True))

        vpn_host = builder.server_address(best_server)
        if use_zap and getattr(self, "zapret_dir", None):
            stop_zapret_process(self.zapret_process)
            self.zapret_process = start_zapret_process(
                self.zapret_dir,
                getattr(self, "zapret_preset", "general.bat"),
                exclude_ip=vpn_host
            )
            self.log(f"[CORE] Zapret запущен (исключая IP VPN-сервера: {vpn_host})")

        if self.xray_process:
            self._reap_xray(self.xray_process)
            self.xray_process = None
            time.sleep(0.2)

        self.xray_process = self._spawn_xray()
        self.is_running = True
        self.log(f"[CORE] Final xray PID: {self.xray_process.pid}")
        self.log(f"[CORE] SOCKS inbound: 127.0.0.1:10808")
        self.log(f"[CORE] HTTP inbound: 127.0.0.1:10809")
        self._conn_name = (best_server.get("remark") or "").strip() or f"Server {best_index}"
        self._conn_ping_ms = ping_ms
        self._connected_at = time.time()
        self.set_status(self._running_status_text(), "green")
        self.log(f"VPN Started Successfully on Server {best_index}.")
        self.set_toggle("СТОП", "#1F4E79", "#2A6299", True)

        self._traffic_up = self._traffic_down = 0
        self._traffic_up_speed = self._traffic_down_speed = 0.0
        self._traffic_last = None
        self._start_traffic_poll()

        if start_watcher and getattr(self, "auto_reconnect", False):
            if self._watcher_thread is None or not self._watcher_thread.is_alive():
                self.log("[CORE] Auto-reconnect watcher started")
                self._watcher_thread = threading.Thread(target=self.auto_reconnect_worker, daemon=True)
                self._watcher_thread.start()

    @staticmethod
    def _fmt_bytes(n):
        value = float(n)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024

    def _start_traffic_poll(self):
        if self._traffic_thread and self._traffic_thread.is_alive():
            return
        self._traffic_thread = threading.Thread(target=self._traffic_poll_loop, daemon=True)
        self._traffic_thread.start()

    def _traffic_poll_loop(self):
        failures = 0
        while self.is_running and failures < 5:
            try:
                up, down = self._query_inbound_traffic()
            except Exception:
                up = down = None
            if up is None:
                failures += 1
            else:
                failures = 0
                now = time.time()
                if self._traffic_last:
                    dt = now - self._traffic_last[0]
                    if dt > 0:
                        self._traffic_up_speed = max(0.0, (up - self._traffic_last[1]) / dt)
                        self._traffic_down_speed = max(0.0, (down - self._traffic_last[2]) / dt)
                self._traffic_last = (now, up, down)
                self._traffic_up, self._traffic_down = up, down
                if self.is_running and self._connected_at:
                    self.set_status(self._running_status_text(), "green")
            time.sleep(3)
        if failures:
            self.log("[CORE] Traffic stats polling stopped (API unavailable)")

    def _query_inbound_traffic(self):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        out = subprocess.run(
            ["xray.exe", "api", "statsquery",
             "-server", f"127.0.0.1:{builder.XRAY_API_PORT}",
             "-pattern", "inbound>>>"],
            capture_output=True, text=True, timeout=5,
            startupinfo=startupinfo,
        )
        if out.returncode != 0:
            return None, None
        try:
            stats = json.loads(out.stdout or "{}").get("stat", [])
        except ValueError:
            return None, None
        up = down = 0
        for stat in stats:
            parts = str(stat.get("name", "")).split(">>>")
            if len(parts) >= 4 and parts[0] == "inbound" and parts[1] != "api-in":
                val = int(stat.get("value", 0) or 0)
                if parts[3] == "uplink":
                    up += val
                elif parts[3] == "downlink":
                    down += val
        return up, down

    def stop_vpn(self):
        self.is_running = False
        if self._background_thread and self._background_thread.is_alive():
            try:
                self._background_thread.join(timeout=2)
            except Exception:
                pass
            self._background_thread = None
        if self.xray_process:
            self._reap_xray(self.xray_process)
            self.xray_process = None
        if self.zapret_process or self.use_zapret:
            stop_zapret_process(self.zapret_process)
            self.zapret_process = None
            self.log("[CORE] Zapret (winws.exe) остановлен")
        self._connected_at = None
        self._conn_name = None
        self._traffic_up = self._traffic_down = 0
        self._traffic_up_speed = self._traffic_down_speed = 0.0
        self._traffic_last = None
        self.set_status("STOPPED", "gray")
        self.log("VPN Stopped by user.")
        self.set_toggle("СТАРТ", "#42A5F5", "#64B5F6", True)

    def _restart_vpn_from_watcher(self):
        if self.is_running:
            self.log("[CORE] Triggering auto-reconnect on main thread...")
            self.stop_vpn()
            self._start_current_mode()

    def auto_reconnect_worker(self):
        self.log("[CORE] Watcher started. Auto-reconnect is active.")
        failed_attempts = 0
        while self.is_running:
            time.sleep(20)
            if not self.is_running:
                break
            if self.xray_process is None:
                continue
            if self._reconnect_in_progress:
                continue

            try:
                s = requests.Session()
                s.trust_env = False
                res = s.get(
                    "https://www.google.com/generate_204",
                    proxies=self.proxy_dict,
                    timeout=(2.0, 4.0)
                )
                if res.status_code == 204:
                    failed_attempts = 0
                    self.log("[CORE] Health check: OK")
                else:
                    failed_attempts += 1
                    self.log(f"[CORE] Health check failed: HTTP {res.status_code}")
            except Exception as e:
                failed_attempts += 1
                self.log(f"[CORE] Health check error: {type(e).__name__}")

            if failed_attempts >= 2:
                if not self.is_running:
                    break
                self.log("[CORE] Connection dropped! Auto-reconnecting...")
                self.set_status("RECONNECTING...", "red")
                failed_attempts = 0
                QTimer.singleShot(0, self._restart_vpn_from_watcher)

    def on_ping_clicked(self):
        if not self.is_running:
            self.log("VPN не запущен. Пинг через прокси невозможен.")
            return
        self.log("Проверка пинга до выбранных сервисов...")
        for name, url in self.check_sites.items():
            threading.Thread(target=self._ping_worker, args=(name, url), daemon=True).start()

    def _ping_worker(self, name, url):
        start_time = time.time()
        try:
            res = requests.get(url, proxies=self.proxy_dict, timeout=5)
            elapsed = int((time.time() - start_time) * 1000)
            if res.status_code in (200, 204):
                msg = f"{name}: OK ({elapsed}ms)"
            else:
                msg = f"{name}: HTTP {res.status_code}"
        except Exception:
            msg = f"{name}: Failed"
        self.log(msg)



    def resizeEvent(self, event):
        super().resizeEvent(event)
        w, h = self.width(), self.height()
        margin = 16
        gap = 10

        # Calculate responsive width for log panel (between 300px and 400px)
        log_w = min(400, max(300, int(w * 0.35)))
        link_w = 180
        status_frame_h = 88
        toggle_w = min(320, max(220, w - log_w - link_w - 60))
        toggle_h = 38
        bottom_panel_h = 84

        logs_left = w - margin - log_w
        self.logs_panel.setGeometry(logs_left, margin, log_w, h - 2 * margin - status_frame_h - 10)
        self.status_frame.setGeometry(logs_left, h - margin - status_frame_h, log_w, status_frame_h)

        self.left_panel.setGeometry(margin, margin, link_w, h - 2 * margin - bottom_panel_h - gap)
        
        # Align bottom_panel to start at the exact same left margin as left_panel (WARP domains, etc.)
        bottom_left = margin
        bottom_w = logs_left - bottom_left - gap
        self.bottom_panel.setGeometry(bottom_left, h - margin - bottom_panel_h, max(200, bottom_w), bottom_panel_h)

        toggle_x = (margin + link_w + logs_left - toggle_w) // 2
        self.btn_toggle.setGeometry(toggle_x, margin + 4, toggle_w, toggle_h)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        w, h = self.width(), self.height()

        if self.bottom_image_path and os.path.exists(self.bottom_image_path):
            pix = QPixmap(self.bottom_image_path)
            if not pix.isNull():
                if self.bottom_crop > 0:
                    visible_h = max(1, pix.height() - self.bottom_crop)
                    pix = pix.copy(0, 0, pix.width(), visible_h)
                scaled = pix.scaledToHeight(h, Qt.TransformationMode.SmoothTransformation)
                x = (w - scaled.width()) // 2 + self.bottom_offset_x
                y = self.bottom_offset_y
                painter.drawPixmap(x, y, scaled)
        else:
            painter.fillRect(0, 0, w, h, QColor(70, 75, 90))

        painter.fillRect(0, 0, w, h, self.overlay_color)

        if self.top_image_path and os.path.exists(self.top_image_path):
            pix = QPixmap(self.top_image_path)
            if not pix.isNull():
                if self.top_crop > 0:
                    visible_h = max(1, pix.height() - self.top_crop)
                    pix = pix.copy(0, 0, pix.width(), visible_h)
                target_h = int(h * 0.95)
                scaled = pix.scaledToHeight(target_h, Qt.TransformationMode.SmoothTransformation)
                x = w // 2 - scaled.width() // 2 - 60 + self.top_offset_x
                y = h - scaled.height() + self.top_offset_y
                painter.drawPixmap(x, y, scaled)

        painter.end()

    def open_settings(self):
        if not hasattr(self, "_settings_dlg") or self._settings_dlg is None or not self._settings_dlg.isVisible():
            self._settings_dlg = SettingsDialog(self)
            main_geo = self.geometry()
            screen = QApplication.primaryScreen()
            avail_w = screen.availableGeometry().width() if screen else 1920
            target_x = main_geo.x() + main_geo.width() + 10
            if target_x + 540 > avail_w:
                target_x = max(20, main_geo.x() - 550)
            self._settings_dlg.move(target_x, main_geo.y())
            self._settings_dlg.show()
        else:
            self._settings_dlg.raise_()
            self._settings_dlg.activateWindow()

    def open_text_file(self, link):
        from dialogs import ConfigTextEditorDialog
        dlg = ConfigTextEditorDialog(self, link)
        dlg.exec()
        self.log(f"Открыт встроенный редактор для {link}")



    def open_ping_sites_dialog(self):
        dlg = PingSitesDialog(self)
        dlg.exec()

    def open_servers_dialog(self):
        dlg = ServerListDialog(self)
        dlg.exec()

    def update_subscription(self, url, sub=None):
        if not url:
            msg = "URL подписки не задан"
            self.log(msg)
            return False, msg
        if sub is None:
            sub = self._active_subscription()
        if sub is None:
            msg = "Нет активной подписки для обновления"
            self.log(msg)
            return False, msg
        output_file = self._subscription_file(sub)
        try:
            self.log(f"Обновление подписки: {url}")
            ok, details = builder.save_decoded_subscription(url, output_file)
            if not ok:
                if os.path.exists(output_file):
                    details += "\nСтарая копия списка серверов сохранена и будет использоваться."
                self.log(f"Ошибка загрузки подписки: {details}")
                return False, details
            sub["url"] = url
            sub["updated_at"] = time.time()
            self.save_settings()
            servers = self._load_servers_for_subscription(sub)
            self.log(f"Подписка обновлена: {details}, всего серверов: {len(servers)}")
            if not servers:
                warning = "Ссылки получены, но ни один сервер не распарсен — проверьте формат подписки"
                self.log(f"WARNING: {warning}")
                return True, warning
            return True, f"Обновлено, серверов: {len(servers)}"
        except Exception as e:
            log_exception("update_subscription failed")
            self.log(f"Ошибка обновления подписки: {e}")
            return False, str(e)

    def _autostart_key(self):
        return r"Software\Microsoft\Windows\CurrentVersion\Run"

    def is_autostart_enabled(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._autostart_key(), 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "GibVPN")
                return bool(value)
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def set_autostart(self, enabled):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._autostart_key(), 0, winreg.KEY_WRITE) as key:
                if enabled:
                    exe_path = sys.executable
                    winreg.SetValueEx(key, "GibVPN", 0, winreg.REG_SZ, f'"{exe_path}"')
                else:
                    try:
                        winreg.DeleteValue(key, "GibVPN")
                    except FileNotFoundError:
                        pass
            self.log(f"Автозапуск Windows {'включён' if enabled else 'выключён'}")
            return True
        except Exception as e:
            log_exception("set_autostart failed")
            self.log(f"Ошибка изменения автозапуска: {e}")
            return False

    def _subscription_file(self, sub):
        if not sub:
            return os.path.join(WORK_DIR, "decoded_sub.txt")
        name = sub.get("name", "sub")
        safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)
        idx = self.subscriptions.index(sub) if sub in self.subscriptions else 0
        return os.path.join(WORK_DIR, f"decoded_sub_{safe_name}_{idx}.txt")

    def _active_subscription(self):
        if not self.subscriptions:
            return None
        if 0 <= self.active_subscription_index < len(self.subscriptions):
            return self.subscriptions[self.active_subscription_index]
        self.active_subscription_index = 0
        return self.subscriptions[0]

    def _load_servers_for_subscription(self, sub):
        sub_file = self._subscription_file(sub)
        if not os.path.exists(sub_file):
            return []
        return builder.get_parsed_servers(sub_file)

    def _server_state(self, sub, server_key):
        if not sub:
            return "unused"
        return sub.get("states", {}).get(server_key, "unused")

    def _set_server_state(self, sub, server_key, state):
        if not sub:
            return
        states = sub.setdefault("states", {})
        if state == "unused":
            states.pop(server_key, None)
        else:
            states[server_key] = state

    def _filter_servers(self, servers, sub):
        states = (sub or {}).get("states", {})
        favorites, regular, blocked = [], [], []
        for srv in servers:
            key = builder.server_key(srv)
            state = states.get(key, "unused")
            if state == "favorite":
                favorites.append(srv)
            elif state == "blocked":
                blocked.append(srv)
            else:
                regular.append(srv)
        return favorites, regular, blocked

    def _get_custom_servers(self):
        servers = []
        for i, link in enumerate(self.custom_links):
            try:
                srv = builder.parse_link(link, f"custom-{i}")
            except Exception:
                srv = None
            if srv:
                servers.append(srv)
        return servers

    def add_custom_link(self, link):
        link = (link or "").strip()
        if not link:
            return False, "Пустая ссылка"
        try:
            srv = builder.parse_link(link, "custom-probe")
        except Exception:
            srv = None
        if srv is None:
            return False, "Ссылка не распознана (поддерживаются vless://, vmess://, trojan://, ss://)"
        key = builder.server_key(srv)
        for existing in self._get_custom_servers():
            if builder.server_key(existing) == key:
                return False, "Такой сервер уже есть в списке"
        self.custom_links.append(link)
        self.save_settings()
        self.log(f"Добавлен свой сервер: {builder.server_key(srv)}")
        return True, f"Сервер успешно добавлен!\n[{srv.get('protocol', '').upper()}] {builder.server_key(srv)}"

    def remove_custom_links_by_indices(self, indices):
        indices_set = set(indices)
        kept = []
        removed = 0
        keys = set()
        for i, link in enumerate(self.custom_links):
            if i in indices_set:
                removed += 1
                try:
                    srv = builder.parse_link(link, "probe")
                    if srv:
                        keys.add(builder.server_key(srv))
                except Exception:
                    pass
            else:
                kept.append(link)
        if removed:
            self.custom_links = kept
            self.save_settings()
            self.log(f"Удалено своих серверов: {removed}")
        return removed

    def remove_custom_servers(self, keys):
        if not keys:
            return 0
        kept = []
        removed = 0
        for link in self.custom_links:
            try:
                srv = builder.parse_link(link, "probe")
                if srv and builder.server_key(srv) in keys:
                    removed += 1
                    continue
            except Exception:
                pass
            kept.append(link)
        if removed:
            self.custom_links = kept
            self.save_settings()
            self.log(f"Удалено своих серверов: {removed}")
        return removed

    def _collect_servers_for_start(self):
        sub = self._active_subscription()
        custom = self._get_custom_servers()
        servers = []
        if sub is not None:
            sub_file = self._subscription_file(sub)
            if os.path.exists(sub_file):
                servers = self._load_servers_for_subscription(sub)
        servers += custom
        if not servers:
            self.set_status("Error: No valid servers found", "red")
            self.log("ERROR: No valid servers parsed!")
            return None, sub
        return servers, sub

    def _active_subscription_info(self):
        sub = self._active_subscription()
        if not sub:
            return "Нет активной подписки"
        count = len(self._load_servers_for_subscription(sub))
        return f"{sub.get('name', 'Без имени')} ({count} серверов)"

    def _zapret_btn_style(self, active=False):
        if active:
            bg = "#00C7BE"
            fg = "#000000"
            border = "2px solid #34C759"
            hover = "#00B3AB"
        else:
            bg = "rgba(0, 0, 0, 95)"
            fg = "#8E8E93"
            border = "1px solid rgba(255, 255, 255, 30)"
            hover = "rgba(0, 0, 0, 120)"
        return f"""
            QPushButton {{
                background-color: {bg};
                border: {border};
                border-radius: 22px;
                font-size: 13px;
                font-weight: bold;
                color: {fg};
                text-align: center;
                padding: 0;
            }}
            QPushButton:hover {{ background-color: {hover}; }}
        """

    def _round_btn_style(self, selected=False):
        if selected:
            bg = "white"
            fg = "#0A84FF"
            hover = "#F0F0F5"
            pressed = "#E2E2E8"
        else:
            bg = "rgba(0, 0, 0, 95)"
            fg = "white"
            hover = "rgba(0, 0, 0, 120)"
            pressed = "rgba(0, 0, 0, 145)"
        return f"""
            QPushButton {{
                background-color: {bg};
                border: 1px solid rgba(0, 0, 0, 45);
                border-radius: 22px;
                font-size: 14px;
                font-weight: bold;
                color: {fg};
                text-align: center;
                padding: 0;
            }}
            QPushButton:hover {{ background-color: {hover}; }}
            QPushButton:pressed {{ background-color: {pressed}; }}
            QPushButton:disabled {{ background-color: rgba(200,200,200,150); color: #666; }}
        """

    def _pill_btn_style(self, accent=""):
        if accent:
            bg = accent
            fg = self._contrast_text(accent)
        else:
            bg = "rgba(255, 255, 255, 235)"
            fg = "#1a1a1a"
        return f"""
            QPushButton {{
                background-color: {bg};
                border: 1px solid rgba(0, 0, 0, 40);
                border-radius: 14px;
                font-size: 14px;
                font-weight: bold;
                color: {fg};
                text-align: center;
                padding: 0;
            }}
            QPushButton:hover {{ background-color: white; color: #1a1a1a; }}
            QPushButton:pressed {{ background-color: #eeeeee; }}
            QPushButton:disabled {{ background-color: rgba(200,200,200,150); color: #666; }}
        """

    def load_settings(self):
        if not hasattr(self, "settings_file") or not self.settings_file:
            appdata_dir = os.path.join(os.environ.get("APPDATA", WORK_DIR), "GibVPN")
            os.makedirs(appdata_dir, exist_ok=True)
            default_path = os.path.join(appdata_dir, "app_settings.json")
            legacy_path = os.path.join(WORK_DIR, "app_settings.json")
            if not os.path.exists(default_path) and os.path.exists(legacy_path):
                try:
                    shutil.copy2(legacy_path, default_path)
                except Exception:
                    pass
            self.settings_file = default_path

        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                self.current_mode = data.get("current_mode", "min")
                self.sub_auto_update_hours = data.get("sub_auto_update_hours", 24)
                self.block_quic = data.get("block_quic", True)

                self.use_zapret = data.get("use_zapret", False)
                self.zapret_dir = data.get("zapret_dir", self.zapret_dir)
                self.zapret_preset = data.get("zapret_preset", "general.bat")

                self.ping_timeout = data.get("ping_timeout", 5.0)
                self.ping_attempts = data.get("ping_attempts", 3)

                color_rgba = data.get("overlay_color")
                if color_rgba and isinstance(color_rgba, list) and len(color_rgba) == 4:
                    self.overlay_color = QColor(*color_rgba)

                self.bottom_image_path = data.get("bottom_image_path")
                self.top_image_path = data.get("top_image_path")
                self.bottom_crop = data.get("bottom_crop", 0)
                self.top_crop = data.get("top_crop", 0)
                self.bottom_offset_x = data.get("bottom_offset_x", 0)
                self.bottom_offset_y = data.get("bottom_offset_y", 0)
                self.top_offset_x = data.get("top_offset_x", 0)
                self.top_offset_y = data.get("top_offset_y", 0)

                w = data.get("window_width")
                h = data.get("window_height")
                if isinstance(w, int) and isinstance(h, int) and w >= 400 and h >= 300:
                    self.resize(w, h)

                self.custom_links = data.get("custom_links", [])

                sites = data.get("check_sites")
                if sites and isinstance(sites, dict):
                    self.check_sites = sites

                subs = data.get("subscriptions", [])
                if subs:
                    self.subscriptions = subs
                    self.active_subscription_index = data.get("active_subscription_index", 0)

                self.log(f"Настройки успешно загружены из {self.settings_file}")
            except Exception as e:
                log_exception("load_settings failed")
                self.log(f"Ошибка загрузки настроек: {e}")

    def save_settings(self):
        settings_file = getattr(self, "settings_file", None)
        if not settings_file:
            appdata_dir = os.path.join(os.environ.get("APPDATA", WORK_DIR), "GibVPN")
            os.makedirs(appdata_dir, exist_ok=True)
            settings_file = os.path.join(appdata_dir, "app_settings.json")
            self.settings_file = settings_file

        data = {
            "current_mode": self.current_mode,
            "autostart_enabled": self.autostart_enabled,
            "sub_auto_update_hours": self.sub_auto_update_hours,
            "block_quic": self.block_quic,
            "use_zapret": getattr(self, "use_zapret", False),
            "zapret_dir": getattr(self, "zapret_dir", ""),
            "zapret_preset": getattr(self, "zapret_preset", "general.bat"),
            "ping_timeout": self.ping_timeout,
            "ping_attempts": self.ping_attempts,
            "overlay_color": [
                self.overlay_color.red(),
                self.overlay_color.green(),
                self.overlay_color.blue(),
                self.overlay_color.alpha()
            ],
            "bottom_image_path": self.bottom_image_path,
            "top_image_path": self.top_image_path,
            "bottom_crop": self.bottom_crop,
            "top_crop": self.top_crop,
            "bottom_offset_x": self.bottom_offset_x,
            "bottom_offset_y": self.bottom_offset_y,
            "top_offset_x": self.top_offset_x,
            "top_offset_y": self.top_offset_y,
            "window_width": self.width(),
            "window_height": self.height(),
            "custom_links": self.custom_links,
            "check_sites": self.check_sites,
            "subscriptions": self.subscriptions,
            "active_subscription_index": self.active_subscription_index
        }
        try:
            with open(settings_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log_exception("save_settings failed")
            self.log(f"Ошибка сохранения настроек: {e}")

    def reset_settings(self):
        self.overlay_color = QColor(173, 216, 230, 120)
        self.bottom_image_path = None
        self.top_image_path = None
        self.bottom_crop = 0
        self.top_crop = 0
        self.bottom_offset_x = 0
        self.bottom_offset_y = 0
        self.top_offset_x = 0
        self.top_offset_y = 0

        self.save_settings()
        self.central.update()
        self.log("Настройки графики сброшены к по умолчанию!")

    def export_full_backup(self):
        return {
            "version": "3.0",
            "exported_at": time.time(),
            "settings": {
                "current_mode": self.current_mode,
                "autostart_enabled": self.autostart_enabled,
                "sub_auto_update_hours": self.sub_auto_update_hours,
                "block_quic": self.block_quic,
                "use_zapret": getattr(self, "use_zapret", False),
                "zapret_dir": getattr(self, "zapret_dir", ""),
                "zapret_preset": getattr(self, "zapret_preset", "general.bat"),
                "ping_timeout": self.ping_timeout,
                "ping_attempts": self.ping_attempts,
                "overlay_color": [
                    self.overlay_color.red(),
                    self.overlay_color.green(),
                    self.overlay_color.blue(),
                    self.overlay_color.alpha()
                ],
                "bottom_image_path": self.bottom_image_path,
                "top_image_path": self.top_image_path,
                "bottom_crop": self.bottom_crop,
                "top_crop": self.top_crop,
                "bottom_offset_x": self.bottom_offset_x,
                "bottom_offset_y": self.bottom_offset_y,
                "top_offset_x": self.top_offset_x,
                "top_offset_y": self.top_offset_y,
                "check_sites": self.check_sites,
                "custom_links": self.custom_links,
            },
            "subscriptions": self.subscriptions,
            "active_subscription_index": self.active_subscription_index,
            "direct_domains": builder.read_text_file(self.exc_file),
            "warp_domains": builder.read_text_file(self.warp_file),
            "direct_apps": builder.read_text_file(getattr(self, "apps_file", os.path.join(WORK_DIR, "direct_apps.txt"))),
        }

    def import_full_backup(self, data):
        if not isinstance(data, dict):
            return False, "Неверный формат резервной копии"

        st = data.get("settings", {})
        if isinstance(st, dict):
            self.current_mode = st.get("current_mode", self.current_mode)
            self.autostart_enabled = st.get("autostart_enabled", self.autostart_enabled)
            self.sub_auto_update_hours = st.get("sub_auto_update_hours", self.sub_auto_update_hours)
            self.block_quic = st.get("block_quic", self.block_quic)
            self.use_zapret = st.get("use_zapret", getattr(self, "use_zapret", False))
            self.zapret_dir = st.get("zapret_dir", getattr(self, "zapret_dir", ""))
            self.zapret_preset = st.get("zapret_preset", getattr(self, "zapret_preset", "general.bat"))
            self.ping_timeout = st.get("ping_timeout", self.ping_timeout)
            self.ping_attempts = st.get("ping_attempts", self.ping_attempts)

            color_rgba = st.get("overlay_color")
            if color_rgba and len(color_rgba) == 4:
                self.overlay_color = QColor(*color_rgba)

            self.bottom_image_path = st.get("bottom_image_path", self.bottom_image_path)
            self.top_image_path = st.get("top_image_path", self.top_image_path)
            self.bottom_crop = st.get("bottom_crop", self.bottom_crop)
            self.top_crop = st.get("top_crop", self.top_crop)
            self.bottom_offset_x = st.get("bottom_offset_x", self.bottom_offset_x)
            self.bottom_offset_y = st.get("bottom_offset_y", self.bottom_offset_y)
            self.top_offset_x = st.get("top_offset_x", self.top_offset_x)
            self.top_offset_y = st.get("top_offset_y", self.top_offset_y)

            sites = st.get("check_sites")
            if sites and isinstance(sites, dict):
                self.check_sites = sites

            self.custom_links = st.get("custom_links", self.custom_links)

        subs = data.get("subscriptions")
        if isinstance(subs, list):
            self.subscriptions = subs
            self.active_subscription_index = data.get("active_subscription_index", 0)

        dd = data.get("direct_domains")
        if isinstance(dd, list):
            try:
                with open(self.exc_file, "w", encoding="utf-8") as f:
                    f.write("".join(dd) if any("\n" in x for x in dd) else "\n".join(dd) + "\n")
            except Exception as e:
                log_exception("import direct_domains failed")

        wd = data.get("warp_domains")
        if isinstance(wd, list):
            try:
                with open(self.warp_file, "w", encoding="utf-8") as f:
                    f.write("".join(wd) if any("\n" in x for x in wd) else "\n".join(wd) + "\n")
            except Exception as e:
                log_exception("import warp_domains failed")

        da = data.get("direct_apps")
        if isinstance(da, list):
            try:
                apps_path = getattr(self, "apps_file", os.path.join(WORK_DIR, "direct_apps.txt"))
                with open(apps_path, "w", encoding="utf-8") as f:
                    f.write("".join(da) if any("\n" in x for x in da) else "\n".join(da) + "\n")
            except Exception as e:
                log_exception("import direct_apps failed")

        self.save_settings()
        self.central.update()
        return True, "Все настройки и подписки успешно импортированы!"


if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        app.setPalette(QPalette(QColor("#F2F2F7")))
        instance_lock = QLockFile(os.path.join(APP_DIR, "gibvpn.lock"))
        if not instance_lock.tryLock(100):
            QMessageBox.warning(
                None, "GibVPN",
                "Приложение GibVPN уже запущено!"
            )
            sys.exit(0)

        win = GibVPNApp()
        win.show()
        sys.exit(app.exec())
    except Exception as e:
        log_exception("Uncaught exception in main window")
        raise
