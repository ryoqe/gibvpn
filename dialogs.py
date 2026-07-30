import os
import sys
import json
import time
import shutil
import urllib.parse
import threading

import builder
import appcore
from appcore import (
    WORK_DIR, log_exception, test_zapret_strategy,
    get_zapret_presets, find_default_zapret_dir
)

from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QLabel, QPlainTextEdit, QFrame, QFileDialog, QColorDialog,
    QMessageBox, QDialog, QSpinBox, QGroupBox, QFormLayout,
    QSlider, QLineEdit, QCheckBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QComboBox, QDoubleSpinBox, QInputDialog
)
from PyQt6.QtGui import QColor, QPixmap, QBrush
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer


class ZapretTestThread(QThread):
    progress_sig = pyqtSignal(int, int, str)
    log_sig = pyqtSignal(str)
    finished_sig = pyqtSignal(str, int)

    def __init__(self, zapret_dir, presets):
        super().__init__()
        self.zapret_dir = zapret_dir
        self.presets = presets

    def run(self):
        try:
            total = len(self.presets)
            best_preset = None
            best_lat = 9999
            for idx, p in enumerate(self.presets, 1):
                short_name = p.split("(")[0].strip() if "(" in p else p
                self.progress_sig.emit(idx, total, short_name)
                self.log_sig.emit(f"[ZAPRET] [{idx}/{total}] Проверка стратегии: \"{p}\"...")

                try:
                    res = test_zapret_strategy(self.zapret_dir, p, timeout=1.5)
                    if isinstance(res, tuple) and len(res) == 3:
                        ok, lat, msg = res
                    else:
                        ok, lat, msg = False, 9999, "Ошибка формата ответа"
                except Exception as ex:
                    ok, lat, msg = False, 9999, str(ex)

                if ok:
                    self.log_sig.emit(f"[ZAPRET]   -> Результат: УСПЕШНО (Пинг: {lat}мс)")
                    if lat < best_lat:
                        best_lat = lat
                        best_preset = p
                else:
                    self.log_sig.emit(f"[ZAPRET]   -> Результат: Не доступно ({msg})")

            self.finished_sig.emit(best_preset or "", best_lat if best_preset else 0)
        except Exception as e:
            log_exception("ZapretTestThread crashed")
            self.log_sig.emit(f"[ZAPRET] Ошибка в потоке тестирования: {e}")
            self.finished_sig.emit("", 0)


class ConfigTextEditorDialog(QDialog):
    """Единый встроенный текстовый редактор конфигураций и списков."""

    FILE_CONFIGS = {
        "#warp": {
            "title": "WARP домены",
            "file": "warp_domains.txt",
            "hint": "Список доменов для маршрутизации через Cloudflare WARP (по одному в строке).\nПример: domain:example.com или geosite:google"
        },
        "#exc": {
            "title": "Исключения (домены)",
            "file": "direct_domains.txt",
            "hint": "Сайты, идущие напрямую в обход VPN (по одному в строке).\nПример: domain:ru, yandex.ru, ya.ru"
        },
        "#apps": {
            "title": "Исключения (приложения)",
            "file": "direct_apps.txt",
            "hint": "Приложения Windows, идущие напрямую в обход VPN (по одному имени exe в строке).\nПример: telegram.exe, discord.exe, steam.exe"
        },
        "#xray": {
            "title": "Конфигурация Xray (config.json)",
            "file": "config.json",
            "hint": "Сгенерированный файл конфигурации Xray. Внимательно проверяйте синтаксис JSON перед сохранением!"
        }
    }

    def __init__(self, parent, target_key):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.parent_app = parent
        self.target_key = target_key
        
        info = self.FILE_CONFIGS.get(target_key, {
            "title": "Редактор файла",
            "file": target_key if not target_key.startswith("#") else "config.txt",
            "hint": "Текстовый файл конфигурации."
        })
        self.title_text = info["title"]
        self.filename = info["file"]
        self.filepath = os.path.join(WORK_DIR, self.filename) if not os.path.isabs(self.filename) else self.filename
        self.hint_text = info["hint"]

        self.setWindowTitle(self.title_text)
        self.resize(640, 520)
        self.setFont(parent.font())
        self.setStyleSheet("""
            QDialog { background-color: #F2F2F7; }
            QLabel { color: #1a1a1a; font-size: 13px; }
            QPushButton {
                background-color: #007AFF; color: white; border: none;
                border-radius: 8px; padding: 7px 16px; font-size: 13px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0066D6; }
        """)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        header = QLabel(f"<b>{self.title_text}</b> — <code>{self.filename}</code>")
        header.setStyleSheet("font-size: 14px; color: #007AFF;")
        layout.addWidget(header)

        hint = QLabel(self.hint_text)
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #666; font-size: 12px; background-color: white; border: 1px solid #E5E5EA; border-radius: 8px; padding: 8px;")
        layout.addWidget(hint)

        self.editor = QPlainTextEdit()
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: 1px solid #D1D1D6;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        self._load_file_content()
        layout.addWidget(self.editor)

        btn_bar = QHBoxLayout()
        btn_bar.addStretch()

        btn_save = QPushButton("Сохранить")
        btn_save.clicked.connect(self._save_file_content)
        btn_bar.addWidget(btn_save)

        btn_cancel = QPushButton("Отмена")
        btn_cancel.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        btn_cancel.clicked.connect(self.reject)
        btn_bar.addWidget(btn_cancel)

        layout.addLayout(btn_bar)

    def _load_file_content(self):
        if os.path.exists(self.filepath):
            try:
                lines = builder.read_text_file(self.filepath)
                self.editor.setPlainText("".join(lines))
            except Exception as e:
                self.editor.setPlainText(f"# Ошибка чтения файла: {e}")
        else:
            self.editor.setPlainText("")

    def _save_file_content(self):
        content = self.editor.toPlainText()
        if self.target_key == "#xray":
            try:
                json.loads(content)
            except Exception as e:
                reply = QMessageBox.question(
                    self, "Синтаксическая ошибка JSON",
                    f"Введенный текст содержит ошибки JSON:\n{e}\n\nВсё равно сохранить?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write(content)
            self.parent_app.log(f"Файл успешно сохранён: {self.filename}")
            QMessageBox.information(self, "Успешно", f"Изменения в файле {self.filename} сохранены!")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка сохранения", f"Не удалось сохранить {self.filename}:\n{e}")


class UpdateDialog(QDialog):
    """Диалог проверки и установки обновлений приложения."""

    def __init__(self, parent):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Обновление GibVPN")
        self.setFixedSize(480, 320)
        self.parent_app = parent
        self.setFont(parent.font())
        self.setStyleSheet("""
            QDialog { background-color: #F2F2F7; }
            QLabel { color: #1a1a1a; font-size: 13px; }
            QPushButton {
                background-color: #007AFF; color: white; border: none;
                border-radius: 8px; padding: 8px 16px; font-size: 13px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0066D6; }
        """)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        self.lbl_status = QLabel("Проверка наличия обновлений на GitHub...")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(self.lbl_status)

        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setReadOnly(True)
        self.notes_edit.setStyleSheet(
            "QPlainTextEdit { background-color: white; border: 1px solid #D1D1D6; "
            "border-radius: 8px; padding: 8px; font-size: 13px; }"
        )
        layout.addWidget(self.notes_edit)

        btn_bar = QHBoxLayout()
        btn_bar.addStretch()

        self.btn_update = QPushButton("Установить обновление")
        self.btn_update.setEnabled(False)
        self.btn_update.clicked.connect(self._start_update)
        btn_bar.addWidget(self.btn_update)

        btn_close = QPushButton("Закрыть")
        btn_close.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)

        layout.addLayout(btn_bar)

        QTimer.singleShot(200, self._check_updates)

    def _check_updates(self):
        def worker():
            tag, url, notes, sha256, size = appcore.get_latest_github_app_info()
            cur_ver = appcore.CURRENT_APP_VERSION
            if tag and appcore.is_newer_version(tag, cur_ver):
                self._update_data = (tag, url, notes, sha256, size)
                self.lbl_status.setText(f"Доступно обновление: v{tag} (у вас v{cur_ver})")
                self.notes_edit.setPlainText(notes or "Список изменений недоступен.")
                self.btn_update.setEnabled(True)
            elif tag:
                self.lbl_status.setText(f"У вас установлена последняя версия v{cur_ver}")
                self.notes_edit.setPlainText("Обновлений не требуется.")
            else:
                self.lbl_status.setText("Не удалось проверить обновления с GitHub.")
                self.notes_edit.setPlainText("Проверьте подключение к сети или VPN.")

        threading.Thread(target=worker, daemon=True).start()

    def _start_update(self):
        if not hasattr(self, "_update_data") or not self._update_data[1]:
            QMessageBox.warning(self, "Ошибка", "URL для скачивания не найден.")
            return

        tag, download_url, _, expected_sha256, expected_size = self._update_data
        self.btn_update.setEnabled(False)
        self.lbl_status.setText(f"Загрузка версии v{tag} (через VPN при необходимости)...")

        def worker():
            ok, path_or_error = appcore.download_github_app_asset(
                download_url, expected_size
            )
            if not ok:
                self.parent_app.log(
                    f"Ошибка скачивания обновления: {path_or_error}"
                )
                QMessageBox.critical(
                    self, "Ошибка",
                    f"Не удалось загрузить обновление.\n\n{path_or_error}"
                )
                return

            filename = "GibVPN_Smart_v3.exe"
            ok, msg = appcore.apply_downloaded_app_update_path(
                path_or_error, filename, expected_sha256
            )
            try:
                os.remove(path_or_error)
            except OSError:
                pass
            if ok:
                self.parent_app.log(msg)
                QMessageBox.information(self, "Обновление", msg)
                self.parent_app._force_quit = True
                self.parent_app.close()

        threading.Thread(target=worker, daemon=True).start()


class SettingsDialog(QDialog):
    """Окно настроек поверх основного окна."""

    def __init__(self, parent):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Настройки")
        screen = QApplication.primaryScreen()
        avail_h = screen.availableGeometry().height() if screen else 900
        self.resize(580, min(840, max(560, avail_h - 100)))
        self.setMinimumSize(500, 480)
        self.parent_app = parent

        self.setFont(parent.font())

        self.setStyleSheet("""
            QDialog {
                background-color: #F2F2F7;
            }
            QLabel {
                color: #1a1a1a;
                font-size: 13px;
            }
            QGroupBox {
                background-color: white;
                color: #1a1a1a;
                font-weight: bold;
                font-size: 14px;
                border: 1px solid #E5E5EA;
                border-radius: 12px;
                margin-top: 10px;
                padding-top: 14px;
                padding-bottom: 10px;
                padding-left: 14px;
                padding-right: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                top: -2px;
                background-color: transparent;
            }
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 6px 12px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #0066D6; }
            QSpinBox, QDoubleSpinBox, QComboBox {
                background-color: #F2F2F7;
                color: #1a1a1a;
                border: 1px solid #D1D1D6;
                border-radius: 8px;
                padding: 4px 8px;
                font-size: 13px;
                min-width: 90px;
                min-height: 24px;
            }
            QCheckBox {
                color: #1a1a1a;
                font-size: 13px;
            }
        """)
        self.setup_ui()
        for widget in self.findChildren(QWidget):
            widget.setFont(self.font())

    def setup_ui(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        # --- Overlay color ---
        group_color = QGroupBox("Оверлей")
        form_color = QFormLayout(group_color)
        form_color.setSpacing(6)
        form_color.setContentsMargins(8, 8, 8, 8)

        self.btn_color = QPushButton("Выбрать цвет")
        self.btn_color.clicked.connect(self.choose_color)
        self.lbl_color = QLabel(f"Текущий: {self.parent_app.overlay_color.name().upper()}")
        self.lbl_color.setStyleSheet("color: #555;")
        form_color.addRow(self.btn_color, self.lbl_color)

        self.slider_alpha = QSlider(Qt.Orientation.Horizontal)
        self.slider_alpha.setRange(0, 255)
        self.slider_alpha.setValue(self.parent_app.overlay_color.alpha())
        self.slider_alpha.valueChanged.connect(self.apply_alpha)
        self.lbl_alpha = QLabel(f"Прозрачность: {self.slider_alpha.value()}")
        self.lbl_alpha.setStyleSheet("color: #555;")
        form_color.addRow(self.lbl_alpha, self.slider_alpha)
        layout.addWidget(group_color)

        # --- Top image (character) ---
        group_top = QGroupBox("Верхнее фото (персонаж)")
        form_top = QFormLayout(group_top)
        form_top.setSpacing(6)
        form_top.setContentsMargins(8, 8, 8, 8)

        self.btn_top = QPushButton("Выбрать файл")
        self.btn_top.clicked.connect(self.choose_top_photo)
        top_name = os.path.basename(self.parent_app.top_image_path) if self.parent_app.top_image_path else "Не выбрано"
        self.lbl_top = QLabel(top_name)
        self.lbl_top.setStyleSheet("color: #777; font-size: 14px;")
        form_top.addRow(self.btn_top, self.lbl_top)

        self.spin_top_crop = QSpinBox()
        self.spin_top_crop.setRange(0, 500)
        self.spin_top_crop.setValue(self.parent_app.top_crop)
        self.spin_top_crop.valueChanged.connect(self.apply_top_crop)
        form_top.addRow("Кроп снизу, px:", self.spin_top_crop)

        self.spin_top_x = QSpinBox()
        self.spin_top_x.setRange(-500, 500)
        self.spin_top_x.setValue(self.parent_app.top_offset_x)
        self.spin_top_x.valueChanged.connect(self.apply_top_offset)
        form_top.addRow("Смещение X:", self.spin_top_x)

        self.spin_top_y = QSpinBox()
        self.spin_top_y.setRange(-500, 500)
        self.spin_top_y.setValue(self.parent_app.top_offset_y)
        self.spin_top_y.valueChanged.connect(self.apply_top_offset)
        form_top.addRow("Смещение Y:", self.spin_top_y)

        layout.addWidget(group_top)

        # --- Bottom image (background) ---
        group_bottom = QGroupBox("Нижнее фото (фон)")
        form_bottom = QFormLayout(group_bottom)
        form_bottom.setSpacing(6)
        form_bottom.setContentsMargins(8, 8, 8, 8)

        self.btn_bottom = QPushButton("Выбрать файл")
        self.btn_bottom.clicked.connect(self.choose_bottom_photo)
        bottom_name = os.path.basename(self.parent_app.bottom_image_path) if self.parent_app.bottom_image_path else "Не выбрано"
        self.lbl_bottom = QLabel(bottom_name)
        self.lbl_bottom.setStyleSheet("color: #777; font-size: 14px;")
        form_bottom.addRow(self.btn_bottom, self.lbl_bottom)

        self.spin_bottom_crop = QSpinBox()
        self.spin_bottom_crop.setRange(0, 500)
        self.spin_bottom_crop.setValue(self.parent_app.bottom_crop)
        self.spin_bottom_crop.valueChanged.connect(self.apply_bottom_crop)
        form_bottom.addRow("Кроп снизу, px:", self.spin_bottom_crop)

        self.spin_bottom_x = QSpinBox()
        self.spin_bottom_x.setRange(-500, 500)
        self.spin_bottom_x.setValue(self.parent_app.bottom_offset_x)
        self.spin_bottom_x.valueChanged.connect(self.apply_bottom_offset)
        form_bottom.addRow("Смещение X:", self.spin_bottom_x)

        self.spin_bottom_y = QSpinBox()
        self.spin_bottom_y.setRange(-500, 500)
        self.spin_bottom_y.setValue(self.parent_app.bottom_offset_y)
        self.spin_bottom_y.valueChanged.connect(self.apply_bottom_offset)
        form_bottom.addRow("Смещение Y:", self.spin_bottom_y)

        layout.addWidget(group_bottom)

        # --- Direct domains (exclusions) ---


        # --- Subscription & autostart ---
        group_misc = QGroupBox("Подписка и автозапуск")
        form_misc = QFormLayout(group_misc)
        form_misc.setSpacing(6)
        form_misc.setContentsMargins(8, 8, 8, 8)

        self.lbl_sub_info = QLabel(self.parent_app._active_subscription_info())
        self.lbl_sub_info.setStyleSheet("color: #555;")
        self.lbl_sub_info.setWordWrap(True)
        form_misc.addRow("Активная:", self.lbl_sub_info)

        self.btn_manage_subs = QPushButton("Управление подписками")
        self.btn_manage_subs.clicked.connect(self.open_subscriptions_manager)
        form_misc.addRow(self.btn_manage_subs)

        self.chk_autostart = QCheckBox("Запускать вместе с Windows")
        self.chk_autostart.setChecked(self.parent_app.is_autostart_enabled())
        self.chk_autostart.stateChanged.connect(self.apply_autostart)
        form_misc.addRow(self.chk_autostart)

        self.lbl_connection_mode = QLabel(
            "Режим «Прокси / Полный VPN» выбирается одним переключателем "
            "на главном экране. Одновременно включить оба режима нельзя."
        )
        self.lbl_connection_mode.setWordWrap(True)
        self.lbl_connection_mode.setStyleSheet("color: #475569;")
        form_misc.addRow("Подключение:", self.lbl_connection_mode)

        self.btn_import_warp = QPushButton("Импортировать личный WARP-профиль")
        self.btn_import_warp.setToolTip("Выберите wgcf-profile.conf. Ключ останется только на этом компьютере.")
        self.btn_import_warp.clicked.connect(self.import_warp_profile)
        form_misc.addRow(self.btn_import_warp)

        self.spin_sub_hours = QSpinBox()
        self.spin_sub_hours.setRange(0, 72)
        self.spin_sub_hours.setValue(self.parent_app.sub_auto_update_hours)
        self.spin_sub_hours.setToolTip("Автоматически обновлять активную подписку каждые N часов (0 — выключено)")
        self.spin_sub_hours.valueChanged.connect(self.apply_sub_hours)
        form_misc.addRow("Автообновление подписки, ч:", self.spin_sub_hours)

        self.spin_ping_timeout = QDoubleSpinBox()
        self.spin_ping_timeout.setRange(1.0, 15.0)
        self.spin_ping_timeout.setSingleStep(0.5)
        self.spin_ping_timeout.setValue(self.parent_app.ping_timeout)
        self.spin_ping_timeout.valueChanged.connect(self.apply_ping_settings)
        form_misc.addRow("Таймаут пинга, сек:", self.spin_ping_timeout)

        self.spin_ping_attempts = QSpinBox()
        self.spin_ping_attempts.setRange(1, 5)
        self.spin_ping_attempts.setValue(self.parent_app.ping_attempts)
        self.spin_ping_attempts.valueChanged.connect(self.apply_ping_settings)
        form_misc.addRow("Попыток пинга:", self.spin_ping_attempts)

        layout.addWidget(group_misc)

        # --- Backup & Restore ---
        group_backup = QGroupBox("Резервное копирование")
        form_backup = QHBoxLayout(group_backup)
        form_backup.setSpacing(10)
        form_backup.setContentsMargins(8, 8, 8, 8)

        self.btn_export = QPushButton("Экспорт настроек")
        self.btn_export.setToolTip("Сохранить все настройки, подписки и домены в JSON файл")
        self.btn_export.clicked.connect(self.export_backup)
        form_backup.addWidget(self.btn_export)

        self.btn_import = QPushButton("Импорт настроек")
        self.btn_import.setToolTip("Восстановить настройки из файла бэкапа JSON")
        self.btn_import.setStyleSheet("QPushButton { background-color: #5856D6; } QPushButton:hover { background-color: #4745B8; }")
        self.btn_import.clicked.connect(self.import_backup)
        form_backup.addWidget(self.btn_import)

        layout.addWidget(group_backup)

        # --- Update ---
        group_update = QGroupBox("Обновления ПО")
        form_update = QHBoxLayout(group_update)
        form_update.setSpacing(10)
        form_update.setContentsMargins(8, 8, 8, 8)

        self.btn_check_update = QPushButton("Проверить обновления на GitHub")
        self.btn_check_update.setStyleSheet("QPushButton { background-color: #34C759; } QPushButton:hover { background-color: #2DB14E; }")
        self.btn_check_update.clicked.connect(self.open_update_dialog)
        form_update.addWidget(self.btn_check_update)

        layout.addWidget(group_update)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)

        bottom_bar = QWidget(self)
        bottom_bar.setStyleSheet("background-color: #E5E5EA; border-top: 1px solid #D1D1D6;")
        bottom_layout = QHBoxLayout(bottom_bar)
        bottom_layout.setContentsMargins(12, 8, 12, 8)
        bottom_layout.setSpacing(10)

        self.btn_reset = QPushButton("Сбросить")
        self.btn_reset.setStyleSheet("QPushButton { background-color: #f44336; } QPushButton:hover { background-color: #d32f2f; }")
        self.btn_reset.clicked.connect(self.reset_settings)
        bottom_layout.addWidget(self.btn_reset)

        bottom_layout.addStretch()

        self.btn_close = QPushButton("Закрыть")
        self.btn_close.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        self.btn_close.clicked.connect(self.accept)
        bottom_layout.addWidget(self.btn_close)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(scroll)
        outer.addWidget(bottom_bar)

    def choose_color(self):
        color = QColorDialog.getColor(self.parent_app.overlay_color, self, "Цвет оверлея")
        if color.isValid():
            self.parent_app.overlay_color = QColor(
                color.red(), color.green(), color.blue(),
                self.parent_app.overlay_color.alpha()
            )
            self.parent_app.central.update()
            self.parent_app.save_settings()
            self.lbl_color.setText(f"Текущий: {color.name().upper()}")
            self.parent_app.log(f"Цвет оверлея изменён: {color.name()}")

    def apply_alpha(self, value):
        self.parent_app.overlay_color.setAlpha(value)
        self.parent_app.central.update()
        self.parent_app.save_settings()
        self.lbl_alpha.setText(f"Прозрачность: {value}")
        self.parent_app.log(f"Прозрачность оверлея: {value}/255")

    def choose_top_photo(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать верхнее фото", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if path:
            test_pix = QPixmap(path)
            if test_pix.isNull():
                self.parent_app.log(f"Ошибка загрузки верхнего фото: {path}")
                return
            self.parent_app.top_image_path = path
            self.lbl_top.setText(os.path.basename(path))
            self.parent_app.central.update()
            self.parent_app.save_settings()
            self.parent_app.log(f"Верхнее фото: {os.path.basename(path)}")

    def apply_top_crop(self, value):
        self.parent_app.top_crop = value
        self.parent_app.central.update()
        self.parent_app.save_settings()
        self.parent_app.log(f"Кроп верхнего фото: {value}px")

    def apply_top_offset(self):
        self.parent_app.top_offset_x = self.spin_top_x.value()
        self.parent_app.top_offset_y = self.spin_top_y.value()
        self.parent_app.central.update()
        self.parent_app.save_settings()
        self.parent_app.log(
            f"Смещение верхнего фото: X={self.parent_app.top_offset_x}, Y={self.parent_app.top_offset_y}"
        )

    def choose_bottom_photo(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать нижнее фото", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if path:
            test_pix = QPixmap(path)
            if test_pix.isNull():
                self.parent_app.log(f"Ошибка загрузки нижнего фото: {path}")
                return
            self.parent_app.bottom_image_path = path
            self.lbl_bottom.setText(os.path.basename(path))
            self.parent_app.central.update()
            self.parent_app.save_settings()
            self.parent_app.log(f"Нижнее фото: {os.path.basename(path)}")

    def apply_bottom_crop(self, value):
        self.parent_app.bottom_crop = value
        self.parent_app.central.update()
        self.parent_app.save_settings()
        self.parent_app.log(f"Кроп нижнего фото: {value}px")

    def apply_bottom_offset(self):
        self.parent_app.bottom_offset_x = self.spin_bottom_x.value()
        self.parent_app.bottom_offset_y = self.spin_bottom_y.value()
        self.parent_app.central.update()
        self.parent_app.save_settings()
        self.parent_app.log(
            f"Смещение нижнего фото: X={self.parent_app.bottom_offset_x}, Y={self.parent_app.bottom_offset_y}"
        )

    def reset_settings(self):
        self.parent_app.reset_settings()
        self.accept()

    def open_subscriptions_manager(self):
        dlg = SubscriptionManagerDialog(self.parent_app, self)
        dlg.exec()
        self.lbl_sub_info.setText(self.parent_app._active_subscription_info())

    def open_update_dialog(self):
        dlg = UpdateDialog(self.parent_app)
        dlg.exec()


    def export_backup(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Экспорт резервной копии", "gibvpn_backup.json", "JSON Files (*.json)"
        )
        if filename:
            try:
                data = self.parent_app.export_full_backup()
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                QMessageBox.information(self, "Успех", f"Настройки успешно экспортированы в:\n{filename}")
                self.parent_app.log(f"Резервная копия экспортирована: {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать настройки: {e}")

    def import_backup(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Импорт резервной копии", "", "JSON Files (*.json)"
        )
        if filename:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ok, msg = self.parent_app.import_full_backup(data)
                if ok:
                    QMessageBox.information(self, "Успех", msg)
                    self.parent_app.log(f"Резервная копия импортирована из: {filename}")
                    self.lbl_sub_info.setText(self.parent_app._active_subscription_info())
                else:
                    QMessageBox.warning(self, "Ошибка", msg)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать файл бэкапа: {e}")

    def apply_quic_setting(self, state):
        self.parent_app.block_quic = (state == Qt.CheckState.Checked.value)
        self.parent_app.save_settings()

    def apply_autostart(self, state):
        enabled = state == Qt.CheckState.Checked.value
        if self.parent_app.set_autostart(enabled):
            self.parent_app.autostart_enabled = enabled
            self.parent_app.save_settings()

    def import_warp_profile(self):
        source, _ = QFileDialog.getOpenFileName(self, "Выберите wgcf-profile.conf", "", "WireGuard profile (*.conf);;Все файлы (*)")
        if not source:
            return
        destination = os.path.join(WORK_DIR, "wgcf-profile.conf")
        try:
            shutil.copy2(source, destination)
            if not builder.get_warp_settings(destination):
                raise ValueError("не найден корректный раздел Interface/Peer")
            self.parent_app.log("Импортирован личный WARP-профиль")
            QMessageBox.information(self, "WARP", "Личный WARP-профиль импортирован. Он не попадает в релизы или GitHub.")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "WARP", f"Не удалось импортировать профиль: {exc}")

    def apply_sub_hours(self, value):
        self.parent_app.sub_auto_update_hours = value
        self.parent_app.save_settings()
        if value:
            self.parent_app.log(f"Автообновление подписки: каждые {value} ч")
        else:
            self.parent_app.log("Автообновление подписки выключено")

    def apply_ping_settings(self, _value=0.0):
        self.parent_app.ping_timeout = float(self.spin_ping_timeout.value())
        self.parent_app.ping_attempts = int(self.spin_ping_attempts.value())
        self.parent_app.save_settings()
        self.parent_app.log(
            f"Пинг: таймаут {self.parent_app.ping_timeout} сек, попыток {self.parent_app.ping_attempts}"
        )


class PingSitesDialog(QDialog):
    """Диалог редактирования списка сайтов для проверки пинга."""

    def __init__(self, parent):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Сайты для пинга")
        self.setFixedSize(400, 360)
        self.parent_app = parent
        self.setFont(parent.font())
        self.setStyleSheet("""
            QDialog { background-color: #F2F2F7; }
            QLabel { color: #1a1a1a; font-size: 14px; }
            QPushButton {
                background-color: #007AFF; color: white; border: none;
                border-radius: 10px; padding: 8px 16px; font-size: 14px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0066D6; }
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        info = QLabel("Каждая строка: Имя URL\nПример: Google https://www.google.com/generate_204")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.text_edit = QPlainTextEdit()
        self.text_edit.setStyleSheet(
            "QPlainTextEdit { background-color: white; border: 1px solid #D1D1D6; "
            "border-radius: 10px; padding: 8px; font-size: 14px; }"
        )
        self._load_text()
        layout.addWidget(self.text_edit)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_save = QPushButton("Сохранить")
        btn_save.clicked.connect(self.save_sites)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

    def _load_text(self):
        lines = [f"{name} {url}" for name, url in self.parent_app.check_sites.items()]
        self.text_edit.setPlainText("\n".join(lines))

    def save_sites(self):
        new_sites = {}
        for line in self.text_edit.toPlainText().strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            name, url = parts
            new_sites[name] = url
        if not new_sites:
            QMessageBox.warning(self, "Пустой список", "Введите хотя бы один сайт.")
            return
        self.parent_app.check_sites = new_sites
        self.parent_app.save_settings()
        self.parent_app.log(f"Сайты для пинга обновлены: {', '.join(new_sites.keys())}")
        self.accept()


class SubscriptionEditDialog(QDialog):
    """Диалог добавления/редактирования подписки."""

    def __init__(self, parent, subscription=None):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Подписка" if subscription else "Новая подписка")
        self.setFixedSize(420, 180)
        self.setFont(parent.font())
        self.setStyleSheet("""
            QDialog { background-color: #F2F2F7; }
            QLabel { color: #1a1a1a; font-size: 14px; }
            QLineEdit {
                background-color: white; color: #1a1a1a; border: 1px solid #D1D1D6;
                border-radius: 8px; padding: 6px; font-size: 14px;
            }
            QPushButton {
                background-color: #007AFF; color: white; border: none;
                border-radius: 10px; padding: 8px 16px; font-size: 14px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0066D6; }
        """)
        self.subscription = subscription or {"name": "", "url": "", "active": False, "states": {}}

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        form = QFormLayout()
        form.setSpacing(10)

        self.edit_name = QLineEdit()
        self.edit_name.setText(self.subscription.get("name", ""))
        self.edit_name.setPlaceholderText("Название подписки")
        form.addRow("Название:", self.edit_name)

        self.edit_url = QLineEdit()
        self.edit_url.setText(self.subscription.get("url", ""))
        self.edit_url.setPlaceholderText("https://example.com/subscription")
        form.addRow("URL:", self.edit_url)

        layout.addLayout(form)
        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_ok = QPushButton("Сохранить")
        btn_ok.clicked.connect(self._on_save)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

    def _on_save(self):
        url = self.edit_url.text().strip()
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                QMessageBox.warning(
                    self, "Неверный URL",
                    "URL подписки должен начинаться с http:// или https:// и содержать хост."
                )
                return
        self.accept()

    def get_subscription(self):
        return {
            "name": self.edit_name.text().strip() or "Без имени",
            "url": self.edit_url.text().strip(),
            "active": self.subscription.get("active", False),
            "states": dict(self.subscription.get("states", {})),
            "pings": dict(self.subscription.get("pings", {})),
            "updated_at": self.subscription.get("updated_at"),
        }


class SubscriptionManagerDialog(QDialog):
    """Диалог управления списком подписок."""

    update_done = pyqtSignal(bool, str, object)
    update_all_done = pyqtSignal(list)

    def __init__(self, app, parent):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Управление подписками")
        self.setMinimumSize(760, 420)
        self.resize(860, 480)
        self.app = app
        self._busy = False
        self._added_sub = None
        self.setFont(parent.font())
        self.setStyleSheet("""
            QDialog { background-color: #F2F2F7; }
            QLabel { color: #1a1a1a; font-size: 14px; }
            QPushButton {
                background-color: #007AFF; color: white; border: none;
                border-radius: 10px; padding: 6px 10px; font-size: 12px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0066D6; }
            QPushButton:disabled { background-color: rgba(200,200,200,150); color: #666; }
            QTableWidget {
                background-color: white; border: 1px solid #D1D1D6;
                border-radius: 10px; gridline-color: #E5E5EA; font-size: 14px;
            }
            QHeaderView::section {
                background-color: #E5E5EA; color: #1a1a1a; font-weight: bold;
                padding: 6px; border: none;
            }
        """)
        self._setup_ui()
        self._refresh_table()
        self.update_done.connect(self._on_update_done)
        self.update_all_done.connect(self._on_update_all_done)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        self._default_info = "Двойной клик по строке — редактировать. Активная подписка используется при запуске VPN."
        self.info = QLabel(self._default_info)
        self.info.setWordWrap(True)
        self.info.setStyleSheet("color: #555;")
        layout.addWidget(self.info)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Имя", "URL", "Серверов", "Обновлена", "Активная", "Статус"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(self.edit_selected)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_add = QPushButton("Добавить")
        self.btn_add.clicked.connect(self.add_subscription)
        btn_layout.addWidget(self.btn_add)

        self.btn_edit = QPushButton("Редактировать")
        self.btn_edit.clicked.connect(self.edit_selected)
        btn_layout.addWidget(self.btn_edit)

        self.btn_remove = QPushButton("Удалить")
        self.btn_remove.clicked.connect(self.remove_selected)
        btn_layout.addWidget(self.btn_remove)

        self.btn_set_active = QPushButton("Сделать активной")
        self.btn_set_active.clicked.connect(self.set_active_selected)
        btn_layout.addWidget(self.btn_set_active)

        self.btn_update = QPushButton("Обновить")
        self.btn_update.clicked.connect(self.update_selected)
        btn_layout.addWidget(self.btn_update)

        self.btn_update_all = QPushButton("Обновить все")
        self.btn_update_all.clicked.connect(self.update_all)
        btn_layout.addWidget(self.btn_update_all)

        self.btn_import = QPushButton("Импорт...")
        self.btn_import.clicked.connect(self.import_subscriptions)
        btn_layout.addWidget(self.btn_import)

        self.btn_export = QPushButton("Экспорт...")
        self.btn_export.clicked.connect(self.export_subscriptions)
        btn_layout.addWidget(self.btn_export)

        btn_close = QPushButton("Закрыть")
        btn_close.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def _refresh_table(self):
        subs = self.app.subscriptions
        self.table.setRowCount(len(subs))
        for i, sub in enumerate(subs):
            servers = self.app._load_servers_for_subscription(sub)
            fav_count = sum(1 for s in sub.get("states", {}).values() if s == "favorite")
            blocked_count = sum(1 for s in sub.get("states", {}).values() if s == "blocked")
            status_parts = []
            if fav_count:
                status_parts.append(f"★{fav_count}")
            if blocked_count:
                status_parts.append(f"⊘{blocked_count}")
            status = " ".join(status_parts) if status_parts else "—"

            updated = sub.get("updated_at")
            updated_text = time.strftime("%d.%m %H:%M", time.localtime(updated)) if updated else "—"

            fg = QBrush(QColor("#1a1a1a"))
            name_item = QTableWidgetItem(sub.get("name", "Без имени"))
            name_item.setForeground(fg)
            name_item.setToolTip(sub.get("name", "Без имени"))
            self.table.setItem(i, 0, name_item)
            url_item = QTableWidgetItem(sub.get("url", ""))
            url_item.setForeground(fg)
            url_item.setToolTip(sub.get("url", ""))
            self.table.setItem(i, 1, url_item)
            count_item = QTableWidgetItem(str(len(servers)))
            count_item.setForeground(fg)
            self.table.setItem(i, 2, count_item)
            updated_item = QTableWidgetItem(updated_text)
            updated_item.setForeground(fg)
            updated_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 3, updated_item)
            active_item = QTableWidgetItem("●" if i == self.app.active_subscription_index else "")
            active_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            active_item.setForeground(fg)
            self.table.setItem(i, 4, active_item)
            status_item = QTableWidgetItem(status)
            status_item.setForeground(fg)
            self.table.setItem(i, 5, status_item)
        self.table.viewport().update()

    def _selected_index(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return rows[0].row()

    def add_subscription(self):
        if self._busy:
            return
        dlg = SubscriptionEditDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        new_sub = dlg.get_subscription()
        if not new_sub["url"]:
            QMessageBox.warning(self, "Ошибка", "URL подписки не может быть пустым.")
            return
        self.app.subscriptions.append(new_sub)
        if len(self.app.subscriptions) == 1:
            self.app.active_subscription_index = 0
        self.app.save_settings()
        self._refresh_table()
        self.app.log(f"Добавлена подписка: {new_sub['name']}")
        self._added_sub = new_sub
        self._start_update(new_sub)

    def edit_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        old_sub = self.app.subscriptions[idx]
        old_file = self.app._subscription_file(old_sub)
        dlg = SubscriptionEditDialog(self, old_sub)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        new_sub = dlg.get_subscription()
        self.app.subscriptions[idx] = new_sub

        new_file = self.app._subscription_file(new_sub)
        if old_file != new_file and os.path.exists(old_file) and not os.path.exists(new_file):
            try:
                shutil.copy2(old_file, new_file)
            except Exception:
                pass

        self.app.save_settings()
        self._refresh_table()
        self.app.log(f"Подписка отредактирована: {new_sub['name']}")

    def remove_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        sub = self.app.subscriptions[idx]
        reply = QMessageBox.question(
            self, "Удаление",
            f"Удалить подписку \"{sub.get('name', 'Без имени')}\"?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        sub_file = self.app._subscription_file(sub)
        try:
            if os.path.exists(sub_file):
                os.remove(sub_file)
        except Exception:
            pass
        del self.app.subscriptions[idx]
        if self.app.active_subscription_index >= len(self.app.subscriptions):
            self.app.active_subscription_index = max(0, len(self.app.subscriptions) - 1)
        self.app.save_settings()
        self._refresh_table()
        self.app.log(f"Удалена подписка: {sub.get('name', 'Без имени')}")

    def set_active_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        self.app.active_subscription_index = idx
        for i, sub in enumerate(self.app.subscriptions):
            sub["active"] = (i == idx)
        self.app.save_settings()
        self._refresh_table()
        self.app.log(f"Активная подписка: {self.app.subscriptions[idx]['name']}")

    def update_selected(self):
        idx = self._selected_index()
        if idx is None or self._busy:
            return
        sub = self.app.subscriptions[idx]
        if not sub.get("url"):
            QMessageBox.warning(self, "Ошибка", "У выбранной подписки не задан URL.")
            return
        self._start_update(sub)

    def update_all(self):
        if self._busy:
            return
        subs = [s for s in self.app.subscriptions if s.get("url")]
        if not subs:
            QMessageBox.information(self, "Обновление", "Нет подписок с URL для обновления.")
            return
        self._set_busy(True, f"Обновление всех подписок ({len(subs)})...")

        def work():
            results = []
            for sub in subs:
                try:
                    ok, details = self.app.update_subscription(sub["url"], sub)
                except Exception as e:
                    ok, details = False, str(e)
                results.append((sub.get("name", "Без имени"), ok, details))
            self.update_all_done.emit(results)

        threading.Thread(target=work, daemon=True).start()

    def _set_busy(self, busy, text=""):
        self._busy = busy
        for btn in (self.btn_add, self.btn_edit, self.btn_remove,
                    self.btn_set_active, self.btn_update, self.btn_update_all):
            btn.setEnabled(not busy)
        self.info.setText(text or self._default_info)

    def _start_update(self, sub):
        if self._busy:
            return
        self._set_busy(True, f"Обновление «{sub.get('name', 'Без имени')}»...")

        def work():
            try:
                ok, details = self.app.update_subscription(sub["url"], sub)
            except Exception as e:
                ok, details = False, str(e)
            self.update_done.emit(ok, details, sub)

        threading.Thread(target=work, daemon=True).start()

    def _on_update_done(self, ok, details, sub):
        added = self._added_sub is sub
        self._added_sub = None
        self._set_busy(False)
        self.app.save_settings()
        self._refresh_table()
        name = sub.get("name", "Без имени")
        if ok:
            if details.startswith("Ссылки получены"):
                title = "Подписка добавлена" if added else "Обновление"
                QMessageBox.warning(self, title, f"{name}\n\n{details}")
        else:
            if added:
                QMessageBox.warning(
                    self, "Ошибка добавления",
                    f"Подписка сохранена, но загрузить не удалось:\n{details}\n\nПроверьте URL и интернет."
                )
                self.app.log(f"Подписка добавлена, но обновление не удалось: {details}")
            else:
                QMessageBox.warning(self, "Ошибка обновления", f"{name}\n\n{details}")

    def _on_update_all_done(self, results):
        self._set_busy(False)
        self.app.save_settings()
        self._refresh_table()
        ok_count = sum(1 for _, ok, _ in results if ok)
        lines = [f"{'OK' if ok else 'FAIL'}  {name}" for name, ok, _ in results]
        QMessageBox.information(
            self, "Обновление завершено",
            f"Успешно: {ok_count}/{len(results)}\n\n" + "\n".join(lines)
        )

    def export_subscriptions(self):
        if not self.app.subscriptions:
            QMessageBox.information(self, "Экспорт", "Список подписок пуст.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт подписок", "subscriptions.json", "JSON (*.json)")
        if not path:
            return
        data = [{"name": s.get("name", ""), "url": s.get("url", "")} for s in self.app.subscriptions]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.app.log(f"Подписки экспортированы: {path}")
            QMessageBox.information(self, "Экспорт", f"Сохранено подписок: {len(data)}\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка экспорта", str(e))

    def import_subscriptions(self):
        path, _ = QFileDialog.getOpenFileName(self, "Импорт подписок", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка импорта", f"Не удалось прочитать файл:\n{e}")
            return
        if not isinstance(data, list):
            QMessageBox.warning(self, "Ошибка импорта", "Ожидается JSON-список подписок.")
            return
        existing = {s.get("url") for s in self.app.subscriptions}
        had_any = bool(self.app.subscriptions)
        added = 0
        for item in data:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            name = str(item.get("name", "")).strip() or "Без имени"
            if not url or url in existing:
                continue
            self.app.subscriptions.append({"name": name, "url": url, "active": False, "states": {}})
            existing.add(url)
            added += 1
        if not had_any and self.app.subscriptions:
            self.app.active_subscription_index = 0
        self.app.save_settings()
        self._refresh_table()
        skipped = len(data) - added
        self.app.log(f"Импорт подписок: добавлено {added}, пропущено {skipped}")
        QMessageBox.information(self, "Импорт", f"Добавлено: {added}\nПропущено (дубликаты/пустые): {skipped}")


class _PingItem(QTableWidgetItem):
    """Ping cell that sorts numerically; unknown/FAIL go last."""

    def __lt__(self, other):
        def _val(item):
            v = item.data(Qt.ItemDataRole.UserRole + 1)
            return v if isinstance(v, (int, float)) else 999999
        return _val(self) < _val(other)


def _ping_color(ms):
    if ms < 200:
        return "#2DB14E"
    if ms <= 500:
        return "#D97A00"
    return "#FF3B30"


class _SpeedItem(QTableWidgetItem):
    """Speed cell sorting numerically in bytes/sec; unknown/FAIL go last."""

    def __lt__(self, other):
        def _val(item):
            v = item.data(Qt.ItemDataRole.UserRole + 1)
            return v if isinstance(v, (int, float)) else -1
        return _val(self) < _val(other)


def _speed_color(speed_bps):
    mbps = speed_bps / (1024 * 1024)
    if mbps >= 5.0:
        return "#2DB14E"
    if mbps >= 1.0:
        return "#D97A00"
    return "#FF3B30"


class ServerListDialog(QDialog):
    """Диалог со списком серверов, избранным, ручным выбором, пингом и замером скорости."""

    ping_update = pyqtSignal(int, str)
    ping_finished = pyqtSignal()
    speed_update = pyqtSignal(int, float, str)
    speed_finished = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Серверы")
        self.setMinimumSize(860, 500)
        self.resize(1020, 600)
        self.parent_app = parent
        self.setFont(parent.font())
        self.ping_update.connect(self._on_ping_update)
        self.ping_finished.connect(self._on_ping_finished)
        self.speed_update.connect(self._on_speed_update)
        self.speed_finished.connect(self._on_speed_finished)
        self.setStyleSheet("""
            QDialog { background-color: #F2F2F7; }
            QLabel { color: #1a1a1a; font-size: 14px; }
            QPushButton {
                background-color: #007AFF; color: white; border: none;
                border-radius: 10px; padding: 6px 12px; font-size: 12px; font-weight: bold;
                min-height: 20px;
            }
            QPushButton:hover { background-color: #0066D6; }
            QPushButton:disabled { background-color: rgba(200,200,200,150); color: #666; }
            QTableWidget {
                background-color: white; alternate-background-color: #F7F8FA;
                border: 1px solid #D1D1D6; border-radius: 10px; gridline-color: #E5E5EA;
                font-size: 14px; selection-background-color: #B8D7FF; selection-color: #1a1a1a;
            }
            QHeaderView::section {
                background-color: #E5E5EA; color: #1a1a1a; font-weight: bold;
                padding: 6px; border: none;
            }
            QComboBox {
                background-color: white; color: #1a1a1a; border: 1px solid #D1D1D6;
                border-radius: 8px; padding: 5px 10px; font-size: 14px; min-width: 150px;
            }
            QComboBox QAbstractItemView {
                background-color: white; color: #1a1a1a; selection-background-color: #B8D7FF;
            }
        """)
        self.servers = []
        self._load_servers()
        self._setup_ui()

    def _load_servers(self):
        idx = self.parent_app.active_subscription_index
        if idx == -1:
            self.servers = []
            for sub in self.parent_app.subscriptions:
                self.servers.extend(self.parent_app._load_servers_for_subscription(sub))
        else:
            sub = self.parent_app._active_subscription()
            if sub is None:
                self.servers = []
            else:
                self.servers = self.parent_app._load_servers_for_subscription(sub)
        self._custom_offset = len(self.servers)
        self.servers = self.servers + self.parent_app._get_custom_servers()

    def _is_custom(self, idx):
        return idx >= self._custom_offset

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        sub = self.parent_app._active_subscription()
        self._sub_name = sub.get("name", "Без имени") if sub else "Нет активной подписки"
        self.info = QLabel()
        self.info.setWordWrap(True)
        self.info.setStyleSheet("color: #555;")
        layout.addWidget(self.info)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.sub_select_combo = QComboBox()
        self._populate_sub_combo()
        self.sub_select_combo.currentIndexChanged.connect(self._on_sub_combo_changed)
        toolbar.addWidget(self.sub_select_combo)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск: название, адрес, протокол...")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setStyleSheet(
            "QLineEdit { background-color: white; color: #1a1a1a; border: 1px solid #D1D1D6; "
            "border-radius: 8px; padding: 6px; font-size: 14px; }"
        )
        self.search_edit.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search_edit, 1)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Все статусы", "★ Избранные", "○ Обычные", "⊘ Заблокированные"])
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        toolbar.addWidget(self.filter_combo)

        self.country_combo = QComboBox()
        self._populate_countries()
        self.country_combo.currentIndexChanged.connect(self._apply_filter)
        toolbar.addWidget(self.country_combo)
        layout.addLayout(toolbar)

        self.table = QTableWidget(len(self.servers), 7)
        self.table.setHorizontalHeaderLabels(["№", "Название", "Сервер", "Пинг", "Скорость", "Статус", "Протокол"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self.toggle_favorite_row)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self._fill_table()
        layout.addWidget(self.table)

        hint = QLabel("Двойной клик — ★ избранное  •  правый клик — меню  •  Ctrl/Shift — выбрать несколько")
        hint.setStyleSheet("color: #8E8E93; font-size: 12px;")
        layout.addWidget(hint)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_ping = QPushButton("Пинг")
        self.btn_ping.clicked.connect(self.ping_selected)
        btn_layout.addWidget(self.btn_ping)

        self.btn_speed = QPushButton("⚡ Скорость")
        self.btn_speed.setToolTip("Замерить реальную скорость скачивания выбранных серверов (в МБ/с)")
        self.btn_speed.clicked.connect(self.speed_selected)
        btn_layout.addWidget(self.btn_speed)

        self.btn_fav = QPushButton("★ Избранное")
        self.btn_fav.clicked.connect(lambda: self.set_state("favorite"))
        btn_layout.addWidget(self.btn_fav)

        self.btn_block = QPushButton("⊘ Заблокировать")
        self.btn_block.setStyleSheet("QPushButton { background-color: #FF3B30; } QPushButton:hover { background-color: #E0342B; }")
        self.btn_block.clicked.connect(lambda: self.set_state("blocked"))
        btn_layout.addWidget(self.btn_block)

        self.btn_unused = QPushButton("○ Обычный")
        self.btn_unused.setStyleSheet("QPushButton { background-color: #AEAEB2; } QPushButton:hover { background-color: #8E8E93; }")
        self.btn_unused.clicked.connect(lambda: self.set_state("unused"))
        btn_layout.addWidget(self.btn_unused)

        self.btn_connect = QPushButton("Подключиться")
        self.btn_connect.setStyleSheet("QPushButton { background-color: #34C759; } QPushButton:hover { background-color: #2DB14E; }")
        self.btn_connect.clicked.connect(self.connect_selected)
        btn_layout.addWidget(self.btn_connect)

        self.btn_add_link = QPushButton("+ По ссылке")
        self.btn_add_link.setToolTip("Добавить сервер вручную ссылкой (без подписки)")
        self.btn_add_link.clicked.connect(self.add_custom_server)
        btn_layout.addWidget(self.btn_add_link)

        btn_close = QPushButton("Закрыть")
        btn_close.setStyleSheet("QPushButton { background-color: #8E8E93; } QPushButton:hover { background-color: #6E6E73; }")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def _populate_sub_combo(self):
        self.sub_select_combo.blockSignals(True)
        self.sub_select_combo.clear()
        self.sub_select_combo.addItem("★ Все подписки (Объединённый список)", -1)
        for i, sub in enumerate(self.parent_app.subscriptions):
            name = sub.get("name", "Подписка")
            self.sub_select_combo.addItem(f"📋 {name}", i)
        cur_idx = self.parent_app.active_subscription_index
        idx_to_select = 0 if cur_idx == -1 else (cur_idx + 1 if 0 <= cur_idx < len(self.parent_app.subscriptions) else 0)
        self.sub_select_combo.setCurrentIndex(idx_to_select)
        self.sub_select_combo.blockSignals(False)

    def _on_sub_combo_changed(self, combo_idx):
        val = self.sub_select_combo.currentData()
        if val is not None:
            self.parent_app.active_subscription_index = val
            self.parent_app.save_settings()
            self._load_servers()
            self._fill_table()
            self._populate_countries()

    def _populate_countries(self):
        self.country_combo.clear()
        self.country_combo.addItem("Все страны", None)
        counts = {}
        for srv in self.servers:
            flag, name = builder.detect_country(srv)
            counts[name] = counts.get(name, 0) + 1
        for name in sorted(counts.keys()):
            flag = next((f for f, n, _ in builder.COUNTRY_MAP if n == name), "🌐")
            self.country_combo.addItem(f"{flag} {name} ({counts[name]})", name)

    def _fill_table(self):
        sub = self.parent_app._active_subscription()
        states = sub.get("states", {}) if sub else {}
        pings = sub.get("pings", {}) if sub else {}
        speeds = sub.get("speeds", {}) if sub else {}

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.servers))

        for i, srv in enumerate(self.servers):
            key = builder.server_key(srv)
            is_cust = self._is_custom(i)

            idx_item = QTableWidgetItem(f"★ {i+1}" if is_cust else str(i + 1))
            idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            idx_item.setData(Qt.ItemDataRole.UserRole, i)
            if is_cust:
                idx_item.setToolTip("Свой сервер (добавлен по ссылке вручную)")
            self.table.setItem(i, 0, idx_item)

            name = (srv.get("remark") or "").strip() or key
            if is_cust and not srv.get("remark"):
                name = f"Свой #{i - self._custom_offset + 1}"
            name_item = QTableWidgetItem(name)
            name_item.setToolTip(name)
            self.table.setItem(i, 1, name_item)

            host = builder.server_address(srv)
            port = builder.server_port(srv)
            addr_text = f"{host}:{port}" if host and port else (host or "—")
            addr_item = QTableWidgetItem(addr_text)
            addr_item.setToolTip(addr_text)
            self.table.setItem(i, 2, addr_item)

            cached_ms = pings.get(key)
            if cached_ms is not None and cached_ms < 9000:
                ping_item = _PingItem(f"{cached_ms} ms")
                ping_item.setForeground(QBrush(QColor(_ping_color(cached_ms))))
                ping_item.setData(Qt.ItemDataRole.UserRole + 1, cached_ms)
            else:
                ping_item = _PingItem("—")
                ping_item.setData(Qt.ItemDataRole.UserRole + 1, 999999)
            ping_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 3, ping_item)

            cached_bps = speeds.get(key)
            if cached_bps is not None and cached_bps > 0:
                sp_str = builder.fmt_speed(cached_bps)
                speed_item = _SpeedItem(sp_str)
                speed_item.setForeground(QBrush(QColor(_speed_color(cached_bps))))
                speed_item.setData(Qt.ItemDataRole.UserRole + 1, cached_bps)
            else:
                speed_item = _SpeedItem("—")
                speed_item.setData(Qt.ItemDataRole.UserRole + 1, -1)
            speed_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 4, speed_item)

            state = states.get(key, "unused")
            if is_cust:
                state_text = "★ Свой"
            elif state == "favorite":
                state_text = "★ Избранный"
            elif state == "blocked":
                state_text = "⊘ Заблокирован"
            else:
                state_text = "○ Обычный"

            state_item = QTableWidgetItem(state_text)
            if state == "favorite":
                state_item.setForeground(QBrush(QColor("#007AFF")))
            elif state == "blocked":
                state_item.setForeground(QBrush(QColor("#FF3B30")))
            elif is_cust:
                state_item.setForeground(QBrush(QColor("#34C759")))
            self.table.setItem(i, 5, state_item)

            proto = (srv.get("protocol") or "—").upper()
            proto_item = QTableWidgetItem(proto)
            proto_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 6, proto_item)

        self._apply_filter()

    def _row_to_server(self, row):
        item = self.table.item(row, 0)
        if item is not None:
            idx = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(idx, int) and 0 <= idx < len(self.servers):
                return idx
        return row

    def _apply_filter(self, *_args):
        needle = self.search_edit.text().strip().lower()
        want = {1: "favorite", 2: "unused", 3: "blocked"}.get(self.filter_combo.currentIndex())
        want_country = self.country_combo.currentData() if hasattr(self, 'country_combo') else None
        sub = self.parent_app._active_subscription()
        states = sub.get("states", {}) if sub else {}
        visible = 0
        for row in range(self.table.rowCount()):
            show = True
            srv_idx = self._row_to_server(row)
            if srv_idx < len(self.servers):
                srv = self.servers[srv_idx]
                if want is not None:
                    key = builder.server_key(srv)
                    show = (states.get(key, "unused") == want)
                if show and want_country:
                    _, cname = builder.detect_country(srv)
                    show = (cname == want_country)
            if show and needle:
                parts = []
                for col in (1, 2, 4, 5):
                    item = self.table.item(row, col)
                    if item:
                        parts.append(item.text().lower())
                show = needle in " ".join(parts)
            self.table.setRowHidden(row, not show)
            if show:
                visible += 1
        self.info.setText(f"Подписка: {self._sub_name} | Показано: {visible} из {len(self.servers)}")

    def _selected_indices(self):
        return sorted(self._row_to_server(index.row()) for index in self.table.selectionModel().selectedRows())

    def _selected_index(self):
        rows = self._selected_indices()
        return rows[0] if rows else None

    def _server_display_name(self, idx):
        srv = self.servers[idx]
        return (srv.get("remark") or "").strip() or builder.server_key(srv)

    def toggle_favorite_row(self, index):
        row = self._row_to_server(index.row())
        if row >= len(self.servers):
            return
        sub = self.parent_app._active_subscription()
        if sub is None:
            return
        key = builder.server_key(self.servers[row])
        current = self.parent_app._server_state(sub, key)
        new_state = "unused" if current == "favorite" else "favorite"
        self.parent_app._set_server_state(sub, key, new_state)
        self.parent_app.save_settings()
        name = self._server_display_name(row)
        self.parent_app.log(f"#{row} {name}: {'★ избранное' if new_state == 'favorite' else '○ обычный'}")
        self._fill_table()

    def _show_context_menu(self, pos):
        if not self._selected_indices():
            return
        menu = QMenu(self)
        act_fav = menu.addAction("★ В избранное")
        act_block = menu.addAction("⊘ Заблокировать")
        act_unused = menu.addAction("○ Обычный")
        menu.addSeparator()
        act_ping = menu.addAction("Пинг")
        act_speed = menu.addAction("⚡ Замерить скорость")
        act_connect = menu.addAction("Подключиться")
        act_delete = None
        if any(self._is_custom(i) for i in self._selected_indices()):
            menu.addSeparator()
            act_delete = menu.addAction("✕ Удалить свой сервер")
        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if act is act_fav:
            self.set_state("favorite")
        elif act is act_block:
            self.set_state("blocked")
        elif act is act_unused:
            self.set_state("unused")
        elif act is act_ping:
            self.ping_selected()
        elif act is act_speed:
            self.speed_selected()
        elif act is act_connect:
            self.connect_selected()
        elif act_delete is not None and act is act_delete:
            self.delete_custom_selected()

    def ping_selected(self):
        indices = self._selected_indices()
        if not indices:
            QMessageBox.information(self, "Выбор", "Выберите хотя бы один сервер из списка.")
            return
        self.btn_ping.setEnabled(False)
        self.btn_ping.setText("Пингуем...")

        sub = self.parent_app._active_subscription()

        def worker():
            for idx in indices:
                srv = self.servers[idx]
                key = builder.server_key(srv)
                host = builder.server_address(srv)
                port = builder.server_port(srv)
                if not host or not port:
                    self.ping_update.emit(idx, "—")
                    continue

                start = time.time()
                try:
                    import socket
                    s = socket.create_connection((host, port), timeout=2.5)
                    s.close()
                    ms = int((time.time() - start) * 1000)
                    text = f"{ms} ms"
                    if sub:
                        sub.setdefault("pings", {})[key] = ms
                except Exception:
                    ms = 9999
                    text = "FAIL"
                    if sub:
                        sub.setdefault("pings", {})[key] = ms

                self.ping_update.emit(idx, text)

            self.ping_finished.emit()

        threading.Thread(target=worker, daemon=True).start()

    def speed_selected(self):
        indices = self._selected_indices()
        if not indices:
            indices = [self._row_to_server(r) for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]
        if not indices:
            QMessageBox.information(self, "Выбор", "Нет серверов для проверки скорости.")
            return

        self.btn_speed.setEnabled(False)
        self.btn_speed.setText("Замер...")
        sub = self.parent_app._active_subscription()

        def worker():
            for idx in indices:
                srv = self.servers[idx]
                key = builder.server_key(srv)
                try:
                    builder.generate_final_config(srv, use_zapret=False, block_quic=True)
                    proc = appcore.start_xray_process(WORK_DIR)
                    time.sleep(0.3)
                    speed_bps, sp_str = builder.measure_server_speed(10808, timeout=2.5)
                    appcore.stop_xray_process(proc)
                    if sub:
                        sub.setdefault("speeds", {})[key] = speed_bps
                    self.speed_update.emit(idx, speed_bps, sp_str)
                except Exception:
                    if sub:
                        sub.setdefault("speeds", {})[key] = 0.0
                    self.speed_update.emit(idx, 0.0, "FAIL")

            self.speed_finished.emit()

        threading.Thread(target=worker, daemon=True).start()

    def _on_speed_update(self, row_idx, speed_bps, text):
        for row in range(self.table.rowCount()):
            if self._row_to_server(row) == row_idx:
                speed_item = _SpeedItem(text)
                speed_item.setData(Qt.ItemDataRole.UserRole + 1, speed_bps)
                if speed_bps > 0:
                    speed_item.setForeground(QBrush(QColor(_speed_color(speed_bps))))
                else:
                    speed_item.setForeground(QBrush(QColor("#FF3B30")))
                speed_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, 4, speed_item)

    def _on_speed_finished(self):
        self.btn_speed.setEnabled(True)
        self.btn_speed.setText("⚡ Скорость")
        self.parent_app.save_settings()
        self.table.setSortingEnabled(True)

    def _on_ping_update(self, row_idx, text):
        for row in range(self.table.rowCount()):
            if self._row_to_server(row) == row_idx:
                try:
                    ms = int(text.replace(" ms", ""))
                except ValueError:
                    ms = 999999

                ping_item = _PingItem(text)
                ping_item.setData(Qt.ItemDataRole.UserRole + 1, ms)
                if ms < 9000:
                    ping_item.setForeground(QBrush(QColor(_ping_color(ms))))
                else:
                    ping_item.setForeground(QBrush(QColor("#FF3B30")))
                ping_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, 3, ping_item)

    def _on_ping_finished(self):
        self.btn_ping.setEnabled(True)
        self.btn_ping.setText("Пинг")
        self.parent_app.save_settings()
        self.table.setSortingEnabled(True)

    def set_state(self, state):
        sub = self.parent_app._active_subscription()
        if sub is None:
            return
        indices = self._selected_indices()
        if not indices:
            return
        for idx in indices:
            key = builder.server_key(self.servers[idx])
            self.parent_app._set_server_state(sub, key, state)
        self.parent_app.save_settings()
        self.parent_app.log(f"Изменён статус {len(indices)} серверов -> {state}")
        self._fill_table()

    def connect_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        srv = self.servers[idx]
        sub = self.parent_app._active_subscription()
        if sub:
            key = builder.server_key(srv)
            self.parent_app._set_server_state(sub, key, "favorite")
        self.parent_app.save_settings()
        name = self._server_display_name(idx)
        self.parent_app.log(f"Сервер #{idx} ({name}) выбран для подключения (★ Избранное)")
        self.accept()
        if self.parent_app.is_running:
            self.parent_app.log("Переподключение к выбранному серверу...")
            self.parent_app.stop_vpn()
        self.parent_app._start_current_mode()

    def add_custom_server(self):
        text, ok = QInputDialog.getText(
            self, "Добавить свой сервер",
            "Вставьте ссылку на сервер (vless://, vmess://, trojan://, ss://):"
        )
        if not ok or not text.strip():
            return
        added_ok, msg = self.parent_app.add_custom_link(text.strip())
        if added_ok:
            QMessageBox.information(self, "Успех", f"{msg}\nСервер появится в конце списка.")
            self._load_servers()
            self._fill_table()
        else:
            QMessageBox.warning(self, "Ошибка", msg)

    def delete_custom_selected(self):
        indices = [i for i in self._selected_indices() if self._is_custom(i)]
        if not indices:
            return
        reply = QMessageBox.question(
            self, "Удаление своих серверов",
            f"Удалить {len(indices)} добавленных вручную серверов?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        custom_indices = [i - self._custom_offset for i in indices]
        self.parent_app.remove_custom_links_by_indices(custom_indices)
        self._load_servers()
        self._fill_table()
