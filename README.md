# GibVPN Smart v3

Десктопный VPN-клиент для Windows на PyQt6 поверх [Xray-core](https://github.com/XTLS/Xray-core).
Лёгкий «яблочный» интерфейс с кастомным фоном, шрифтом и слоем персонажа.

## Возможности

- Подписки на серверы: `vless://`, `vmess://`, `trojan://`, `ss://` (несколько подписок, активная выбирается).
- Список серверов: названия из подписки, поиск и фильтр по статусу, цветной пинг, контекстное меню.
- Избранное / блокировка: двойной клик, правый клик или кнопки; выбор нескольких серверов (Ctrl/Shift).
- Два режима автовыбора сервера:
  - **МИН** — сервер с минимальным пингом;
  - **МАКС** — сервер с максимальной доступностью проверочных сайтов.
- Маршрутизация: исключения напрямую (`direct_domains.txt`), часть доменов через Cloudflare WARP (`warp_domains.txt`, wireguard-аутбаунд через основной сервер).
- Локальные прокси после подключения: SOCKS5 `127.0.0.1:10808`, HTTP `127.0.0.1:10809`.
- Автопереподключение при обрыве, фоновая проверка «обычных» серверов после подключения к избранному.
- Иконка в трее (закрытие окна сворачивает приложение), защита от второй копии.
- Автозапуск с Windows, атомарное сохранение настроек, ротация лога ошибок (5 МБ).

## Структура

| Файл | Назначение |
|---|---|
| `gui.py` | Весь UI и логика VPN (PyQt6) |
| `builder.py` | Парсинг ссылок подписок, генерация `config.json` для xray |
| `appcore.py` | Пути (APP_DIR/WORK_DIR), лог ошибок с ротацией, завершение процессов |
| `build.py` / `build.bat` | Сборка exe: тесты → PyInstaller → тесты → превью |
| `GibVPN_Smart_v3.spec` | Конфиг PyInstaller (onedir) |
| `screenshot_tool.py` | Скриншоты окон для превью |
| `tests/test_no_xray.py` | Тесты без запуска xray (оффскрин) |
| `tests/test_all.py` | Ручной тест: пинг всех серверов через реальный xray |
| `ofont.ru_Zeequada.ttf` | Дизайнерский шрифт (кладётся рядом с exe при сборке) |
| `ROADMAP.md` | План развития |

## Запуск из исходников

```bat
python -m venv venv
venv\Scripts\pip install PyQt6 requests pyinstaller
run_gui.bat
```

## Сборка exe

```bat
build.bat
```

Результат: `dist\GibVPN_Smart_v3\GibVPN_Smart_v3.exe` (+ `xray.exe`, `geo*.dat`, шрифт и списки доменов рядом).

## Тесты

```bat
set QT_QPA_PLATFORM=offscreen
venv\Scripts\python tests\test_no_xray.py -v
```

## Данные пользователя

Рядом с exe (portable-режим), либо в `%LOCALAPPDATA%\GibVPN`, если папка недоступна для записи:
`app_settings.json`, `decoded_sub*.txt` (кэши подписок), `gibvpn_error.log`, `gibvpn.lock`.

## Благодарности

- [Xray-core](https://github.com/XTLS/Xray-core) — ядро прокси (лицензия MPL 2.0, см. `LICENSE`).
- Cloudflare WARP — для wireguard-аутбаунда.
