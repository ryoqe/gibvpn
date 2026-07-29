# GibVPN Smart v3.0

[![Release](https://img.shields.io/github/v/release/ryoqe/gibvpn?style=for-the-badge&color=007AFF)](https://github.com/ryoqe/gibvpn/releases/latest)
[![Download](https://img.shields.io/badge/Скачать-Windows%20x64-34C759?style=for-the-badge&logo=windows)](https://github.com/ryoqe/gibvpn/releases/latest)
[![Python](https://img.shields.io/badge/PyQt6-3.10+-38BDF8?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/Лицензия-MIT-orange?style=for-the-badge)](LICENSE)

Современный, быстрый и удобный десктопный VPN-клиент для Windows на базе **PyQt6** и **Xray-core** с поддержкой **Zapret DPI bypass**, замером реальной скорости и объединённым режимом всех подписок.

---

## 🚀 Скачивание и быстрая установка

Чтобы использовать приложение, **НЕ НУЖНО** устанавливать Python или компилировать код!

### 📥 1. Готовый исполняемый файл (.exe)

Нажмите на кнопку ниже, чтобы перейти на страницу релизов и скачать готовый портативный архив:

👉 **[СКАЧАТЬ ПОСЛЕДНЮЮ РЕЛИЗНУЮ ВЕРСИЮ (GitHub Releases)](https://github.com/ryoqe/gibvpn/releases/latest)**

Или прямая ссылка на архив релиза:
- 📦 [GibVPN_Smart_v3.0.1_Windows_x64.zip](https://github.com/ryoqe/gibvpn/releases/download/v3.0.1/GibVPN_Smart_v3.0.1_Windows_x64.zip)

### 📂 Инструкция по запуску:
1. Скачайте архив **`GibVPN_Smart_v3.0.0_Windows_x64.zip`**.
2. Распакуйте содержимое архива в любую папку на компьютере (например, `C:\GibVPN`).
3. Запустите файл **`GibVPN_Smart_v3.exe`**.

---

## 🔥 Главные возможности

- **⚡ 4 Режима автовыбора серверов**:
  - **МИН**: подключается к серверу с наименьшей задержкой (пингом).
  - **МАКС**: выбирает сервер с наибольшим количеством доступных проверочных сайтов (YouTube, Google, Telegram и др.).
  - **СКОРОСТЬ**: замеряет скорость реального скачивания (МБ/с) и выбирает самый быстрый сервер.
  - **АВТО**: выполняет комплексный тест (пинг + доступность + скорость) и подключается к лучшему серверу по совокупному баллу.
- **🛡 Обход блокировок DPI (Zapret / WinWS)**:
  - Автоматическое исключение IP-адреса VPN-сервера (`--outbound-out-exclude-ip`), благодаря чему Zapret не ломает VPN-туннель.
- **📊 Замер реальной скорости (Speedtest)**:
  - Проверка пропускной способности серверов (в МБ/с и КБ/с) через изолированные тестовые соксы.
- **★ Объединённый режим «Все подписки»**:
  - Просмотр, замер и единое управление статусами (Избранное / Заблокирован) для серверов из всех подписок сразу.
- **📝 Встроенный редактор конфигураций**:
  - Открытие и редактирование `warp_domains.txt`, `direct_domains.txt`, `direct_apps.txt` и `config.json` прямо внутри приложения.
- **💾 Полный Экспорт / Импорт настроек**:
  - Сохранение и восстановление всех подписок, доменов, приложений и графических настроек в единый `.json` файл.
- **🔄 Автообновления через GitHub**:
  - Автоматическая проверка и загрузка новых релизов с поддержкой прокси/VPN на случай блокировки GitHub в РФ.
- **🌐 Поддерживаемые протоколы**:
  - `VLESS` (включая REALITY, XHTTP, gRPC, WebSocket, TCP), `VMess`, `Trojan`, `Shadowsocks`.

---

## 🛠 Запуск из исходного кода (Для разработчиков)

Если вы хотите вносить изменения в исходный код или запустить проект локально:

```bat
# 1. Клонировать репозиторий
git clone https://github.com/ryoqe/gibvpn.git
cd gibvpn

# 2. Создать виртуальное окружение и установить зависимости
python -m venv venv
venv\Scripts\pip install PyQt6 requests pyinstaller

# 3. Запустить приложение
run_gui.bat
```

### 🧪 Запуск тестов:
```bat
venv\Scripts\python tests/test_no_xray.py -v
```

### 📦 Сборка собственного .exe:
```bat
build.bat
```
Результат сборки появится в папке `dist\GibVPN_Smart_v3\GibVPN_Smart_v3.exe`.

---

## 🔒 Конфиденциальность и безопасность

- Приложение **НЕ СОБИРАЕТ** и **НЕ ОТПРАВЛЯЕТ** ваши персональные данные, ключи или ссылки подписок на внешние сервера.
- Все файлы конфигураций (`app_settings.json`, ключи WARP, домены) хранятся исключительно на вашем локальном компьютере.

---

## 📄 Лицензия и благодарности

- **Xray-core** — прокси-ядро (лицензия [MPL 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)).
- **Zapret** — компонент обхода DPI ([WinWS](https://github.com/bol-van/zapret)).
