"""
Shared application plumbing: data/work directories, error log, child processes.

This module intentionally has no Qt imports so it can be used from anywhere
(gui, tests, tools) without pulling in PyQt6.
"""
import os
import sys
import shutil
import time
import traceback

# PyInstaller sets sys.stdout/sys.stderr to None for windowed apps.
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')


def get_app_dir():
    """
    Persistent directory for user data: settings, logs, subscriptions (%APPDATA%\\GibVPN).
    Guarantees that user settings, subscriptions, and custom rules are preserved
    between application builds, updates, and executable versions.
    """
    app_data_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'GibVPN')
    os.makedirs(app_data_dir, exist_ok=True)

    if getattr(sys, 'frozen', False):
        base_src = os.path.dirname(sys.executable)
    else:
        base_src = os.path.dirname(os.path.abspath(__file__))

    # Seed initial user configuration files if not present in APPDATA
    for item in ("app_settings.json", "direct_domains.txt", "direct_apps.txt", "warp_domains.txt", "assets", "singbox_bin"):
        src = os.path.join(base_src, item)
        dst = os.path.join(app_data_dir, item)
        if not os.path.exists(src) and item == "app_settings.json":
            src = os.path.join(base_src, "app_settings.json.example")
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
            except Exception:
                pass
    return app_data_dir


def get_work_dir(app_dir):
    """
    Directory that contains xray.exe and helper data files.
    When helpers already live next to the executable (or when running from
    source), this is the same as app_dir. In a PyInstaller onefile bundle the
    helpers are unpacked into a temporary _MEIPASS directory; copy them to
    app_dir once so they (and the settings/config written alongside them)
    persist across restarts.
    """
    if os.path.exists(os.path.join(app_dir, "xray.exe")):
        return app_dir

    meipass = getattr(sys, '_MEIPASS', None)
    if meipass and os.path.exists(os.path.join(meipass, "xray.exe")):
        helpers = [
            'xray.exe', 'geoip.dat', 'geosite.dat',
            'direct_domains.txt', 'warp_domains.txt',
            'wgcf-account.toml', 'wgcf-profile.conf',
            'decoded_sub.txt', 'ofont.ru_Zeequada.ttf',
        ]
        # Also migrate any per-subscription cached files that were bundled.
        for name in os.listdir(meipass):
            if name.startswith('decoded_sub_') and name.endswith('.txt'):
                helpers.append(name)

        for name in helpers:
            src = os.path.join(meipass, name)
            dst = os.path.join(app_dir, name)
            if not os.path.exists(src) or os.path.exists(dst):
                continue
            try:
                shutil.copy2(src, dst)
            except Exception:
                pass

        if os.path.exists(os.path.join(app_dir, "xray.exe")):
            return app_dir

        # If copying failed for some reason, fall back to the temp dir so the
        # app can at least start.
        return meipass

    return app_dir


def find_singbox_exe():
    """Find the bundled sing-box executable without relying on PATH."""
    base = os.path.join(WORK_DIR, "singbox_bin")
    if not os.path.isdir(base):
        return None
    for root, _dirs, files in os.walk(base):
        if "sing-box.exe" in files:
            return os.path.join(root, "sing-box.exe")
    return None


def is_windows_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


APP_DIR = get_app_dir()
WORK_DIR = get_work_dir(APP_DIR)

# Only these per-user Internet Settings values are touched by the optional
# system-proxy mode.  WinHTTP is deliberately never changed.
SYSTEM_PROXY_VALUES = (
    "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect",
)
SYSTEM_PROXY_BACKUP_PATH = os.path.join(APP_DIR, "system_proxy_backup.json")


def read_windows_system_proxy():
    """Return exactly the Internet Settings values that GibVPN may change."""
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    snapshot = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
        for name in SYSTEM_PROXY_VALUES:
            try:
                value, value_type = winreg.QueryValueEx(key, name)
                snapshot[name] = {"exists": True, "value": value, "type": value_type}
            except FileNotFoundError:
                snapshot[name] = {"exists": False}
    return snapshot


def restore_windows_system_proxy(snapshot):
    """Restore a prior snapshot without touching unrelated proxy settings."""
    import winreg
    if not snapshot:
        return
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        for name in SYSTEM_PROXY_VALUES:
            item = snapshot.get(name, {"exists": False})
            if item.get("exists"):
                winreg.SetValueEx(key, name, 0, item["type"], item["value"])
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass


def enable_windows_system_proxy(server="127.0.0.1:10809"):
    """Enable a user-level Windows proxy and return its restorable old state."""
    import winreg
    snapshot = read_windows_system_proxy()
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>;localhost;127.0.0.1;::1")
        winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
    return snapshot


def save_windows_system_proxy_backup(snapshot):
    """Persist a backup so a later launch can recover after a crash."""
    import json
    temp_path = SYSTEM_PROXY_BACKUP_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle)
    os.replace(temp_path, SYSTEM_PROXY_BACKUP_PATH)


def clear_windows_system_proxy_backup():
    try:
        os.remove(SYSTEM_PROXY_BACKUP_PATH)
    except FileNotFoundError:
        pass


def recover_windows_system_proxy():
    """Restore only a proxy configuration that still points to GibVPN itself."""
    import json
    if not os.path.exists(SYSTEM_PROXY_BACKUP_PATH):
        return False
    try:
        with open(SYSTEM_PROXY_BACKUP_PATH, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
        current = read_windows_system_proxy()
        is_ours = (current.get("ProxyEnable", {}).get("value") == 1 and
                   current.get("ProxyServer", {}).get("value") == "127.0.0.1:10809")
        if is_ours:
            restore_windows_system_proxy(snapshot)
        clear_windows_system_proxy_backup()
        return is_ours
    except (OSError, ValueError):
        return False

# Migrate settings/cache from a previous one-file install located in the parent
# directory (e.g. dist/GibVPN_Smart_v3.exe + dist/app_settings.json) to the
# new one-dir install (e.g. dist/GibVPN_Smart_v3/GibVPN_Smart_v3.exe).
if getattr(sys, 'frozen', False):
    _parent_dir = os.path.dirname(APP_DIR)
    _old_settings = os.path.join(_parent_dir, "app_settings.json")
    _new_settings = os.path.join(APP_DIR, "app_settings.json")
    if _parent_dir != APP_DIR and os.path.exists(_old_settings) and not os.path.exists(_new_settings):
        try:
            shutil.copy2(_old_settings, _new_settings)
        except Exception:
            pass
        for _name in os.listdir(_parent_dir):
            if _name.startswith("decoded_sub") and _name.endswith(".txt"):
                _src = os.path.join(_parent_dir, _name)
                _dst = os.path.join(APP_DIR, _name)
                if os.path.exists(_src) and not os.path.exists(_dst):
                    try:
                        shutil.copy2(_src, _dst)
                    except Exception:
                        pass

os.chdir(WORK_DIR)
LOG_PATH = os.path.join(APP_DIR, "gibvpn_error.log")
MAX_LOG_BYTES = 5 * 1024 * 1024  # rotate the error log past 5 MB


def log_exception(msg):
    try:
        if os.path.getsize(LOG_PATH) > MAX_LOG_BYTES:
            # Rotate: keep a single previous generation.
            os.replace(LOG_PATH, LOG_PATH + ".old")
    except Exception:
        pass
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        traceback.print_exc(file=f)
        f.write("\n")


def terminate_process(proc, timeout=1):
    """Terminate a child process, escalating to kill() if it ignores terminate()."""
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
DEFAULT_ZAPRET_PATH = os.path.join(desktop_dir, "zapret-discord-youtube-1.9.9c", "zapret-discord-youtube-1.9.9c")


def find_default_zapret_dir(custom_path=None):
    """Return valid Zapret directory if found, otherwise None."""
    candidates = []
    if custom_path:
        candidates.append(custom_path)

    # 1. Internal bundled zapret_bin in WORK_DIR or APP_DIR
    candidates.append(os.path.join(WORK_DIR, "zapret_bin"))
    candidates.append(os.path.join(APP_DIR, "zapret_bin"))

    # 2. External desktop fallback
    candidates.append(DEFAULT_ZAPRET_PATH)
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    candidates.append(os.path.join(desktop, "zapret-discord-youtube-1.9.9c", "zapret-discord-youtube-1.9.9c"))

    for path in candidates:
        if path and os.path.exists(path):
            if os.path.exists(os.path.join(path, "winws.exe")) or os.path.exists(os.path.join(path, "bin", "winws.exe")):
                return path
    return None


ZAPRET_BUILTIN_STRATEGIES = {
    "Встроенный Универсальный (YouTube + Discord + РКН)": {
        "isp": "Ростелеком, ТТК, МТС, Мегафон, Дом.ру",
        "cmd": lambda b: [
            b,
            "--wf-tcp=80,443,2053,2083,2087,2096,8443", "--wf-udp=443,19294-19344,50000-50100",
            "--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-repeats=11", f"--dpi-desync-fake-quic={os.path.join(os.path.dirname(b), 'quic_initial_www_google_com.bin')}", "--new",
            "--filter-udp=19294-19344,50000-50100", "--filter-l7=discord,stun", "--dpi-desync=fake", f"--dpi-desync-fake-discord={os.path.join(os.path.dirname(b), 'quic_initial_dbankcloud_ru.bin')}", f"--dpi-desync-fake-stun={os.path.join(os.path.dirname(b), 'quic_initial_dbankcloud_ru.bin')}", "--dpi-desync-repeats=6", "--new",
            "--filter-tcp=2053,2083,2087,2096,8443", "--hostlist-domains=discord.media", "--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2", "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={os.path.join(os.path.dirname(b), 'tls_clienthello_www_google_com.bin')}", f"--dpi-desync-fake-tls={os.path.join(os.path.dirname(b), 'tls_clienthello_www_google_com.bin')}", "--new",
            "--filter-tcp=80,443", "--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=664", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2", "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={os.path.join(os.path.dirname(b), 'tls_clienthello_max_ru.bin')}", f"--dpi-desync-fake-tls={os.path.join(os.path.dirname(b), 'tls_clienthello_max_ru.bin')}"
        ]
    },
    "Супер-Альт (SUPER_ALT - Билайн / Мегафон / Yota)": {
        "isp": "Билайн, Мегафон, Yota (усиленная борьба с ТСПУ)",
        "cmd": lambda b: [
            b,
            "--wf-tcp=80,443,8443", "--wf-udp=443,19294-19344",
            "--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-repeats=8", f"--dpi-desync-fake-quic={os.path.join(os.path.dirname(b), 'quic_initial_www_google_com.bin')}", "--new",
            "--filter-tcp=80,443", "--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts", f"--dpi-desync-fake-tls={os.path.join(os.path.dirname(b), 'tls_clienthello_www_google_com.bin')}"
        ]
    },
    "Fake TLS (МТС Мобильный / Tele2)": {
        "isp": "МТС Мобильный, Tele2, Kcell",
        "cmd": lambda b: [
            b,
            "--wf-tcp=80,443,8443", "--wf-udp=443",
            "--filter-tcp=80,443", "--dpi-desync=fake", "--dpi-desync-repeats=6", f"--dpi-desync-fake-tls={os.path.join(os.path.dirname(b), 'tls_clienthello_max_ru.bin')}"
        ]
    }
}


def get_zapret_presets(zapret_dir):
    """List available strategy presets or *.bat files in Zapret directory."""
    presets = list(ZAPRET_BUILTIN_STRATEGIES.keys())
    if not zapret_dir or not os.path.exists(zapret_dir):
        return presets
    try:
        search_dir = zapret_dir if os.path.exists(os.path.join(zapret_dir, "general.bat")) else os.path.dirname(zapret_dir)
        if os.path.exists(search_dir):
            for f in os.listdir(search_dir):
                if f.lower().startswith("general") and f.lower().endswith(".bat"):
                    if f not in presets:
                        presets.append(f)
    except Exception:
        pass
    return presets


def start_zapret_process(zapret_dir, preset_bat="Встроенный Универсальный (YouTube + Discord + РКН)", exclude_ip=None):
    """Launch winws.exe via preset batch script or built-in engine in background."""
    if not zapret_dir or not os.path.exists(zapret_dir):
        return None

    if os.path.exists(os.path.join(zapret_dir, "winws.exe")):
        bin_dir = zapret_dir
        winws_bin = os.path.join(zapret_dir, "winws.exe")
    elif os.path.exists(os.path.join(zapret_dir, "bin", "winws.exe")):
        bin_dir = os.path.join(zapret_dir, "bin")
        winws_bin = os.path.join(bin_dir, "winws.exe")
    else:
        return None

    import subprocess
    creationflags = 0x08000000  # CREATE_NO_WINDOW

    if preset_bat in ZAPRET_BUILTIN_STRATEGIES:
        cmd = ZAPRET_BUILTIN_STRATEGIES[preset_bat]["cmd"](winws_bin)
        cwd = bin_dir
    else:
        bat_path = os.path.join(zapret_dir, preset_bat)
        if not os.path.exists(bat_path):
            bat_path = os.path.join(os.path.dirname(zapret_dir), preset_bat)

        if os.path.exists(bat_path) and preset_bat.endswith(".bat"):
            cmd = ["cmd.exe", "/c", bat_path]
            cwd = os.path.dirname(bat_path)
        else:
            cmd = ZAPRET_BUILTIN_STRATEGIES["Встроенный Универсальный (YouTube + Discord + РКН)"]["cmd"](winws_bin)
            cwd = bin_dir

    if exclude_ip and isinstance(cmd, list) and cmd and cmd[0].endswith("winws.exe"):
        ip_to_exclude = exclude_ip
        try:
            import socket
            ip_to_exclude = socket.gethostbyname(exclude_ip)
        except Exception:
            pass
        cmd.extend([f"--outbound-out-exclude-ip={ip_to_exclude}"])

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            creationflags=creationflags
        )
        return proc
    except OSError as e:
        if getattr(e, 'winerror', None) == 740 or '740' in str(e):
            # Try elevated launch via ShellExecuteW
            try:
                import ctypes
                cmd_args = " ".join([f'"{arg}"' if " " in arg else arg for arg in cmd[1:]])
                res = ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd[0], cmd_args, cwd, 0)
                if res > 32:
                    return "elevated"
            except Exception as ex:
                log_exception(f"ShellExecute failed: {ex}")
            return "need_admin"
        log_exception(f"Failed to start Zapret process: {e}")
        return None
    except Exception as e:
        log_exception(f"Failed to start Zapret process: {e}")
        return None


def stop_zapret_process(proc=None):
    """Stop Zapret process quickly and clean up winws.exe child tasks."""
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=0.5)
        except Exception:
            pass
    try:
        import subprocess
        subprocess.run(["taskkill", "/F", "/IM", "winws.exe"], capture_output=True, timeout=1)
    except Exception:
        pass


def test_zapret_strategy(zapret_dir, preset_name, timeout=1.5):
    """Test a Zapret strategy against YouTube without proxy or environment interference."""
    import time, requests, os
    env_proxies = {k: os.environ.pop(k) for k in list(os.environ.keys()) if "proxy" in k.lower()}
    proc = None
    try:
        # Kill any prior winws instance first so winws.exe can bind to WinDivert driver
        stop_zapret_process(None)

        proc = start_zapret_process(zapret_dir, preset_name)
        if proc == "need_admin":
            return False, 9999, "Запустите от Администратора"
        if not proc:
            return False, 9999, "Не удалось запустить winws"
        time.sleep(0.5)
        start_t = time.time()
        s = requests.Session()
        s.trust_env = False
        r1 = s.get("https://www.youtube.com/generate_204", timeout=timeout)
        lat = int((time.time() - start_t) * 1000)
        ok = r1.status_code in (200, 204)
        msg = f"ОК ({lat}мс)" if ok else f"Код ответа: YT={r1.status_code}"
        return ok, lat, msg
    except Exception as e:
        err_str = str(e)
        if "ConnectTimeout" in err_str or "ReadTimeout" in err_str:
            err_str = "Таймаут (заблокирован)"
        return False, 9999, err_str
    finally:
        os.environ.update(env_proxies)
        if proc and proc != "elevated" and proc != "need_admin":
            stop_zapret_process(proc)


def check_zapret_service_installed():
    """Check if Zapret Windows Service is installed."""
    import subprocess
    try:
        res = subprocess.run(["sc", "query", "zapret"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0 and "RUNNING" in res.stdout:
            return True, "Служба работает (RUNNING)"
        elif res.returncode == 0:
            return True, "Служба установлена (Остановлена)"

        res_winws = subprocess.run(["sc", "query", "winws"], capture_output=True, text=True, timeout=2)
        if res_winws.returncode == 0:
            return True, "Служба установлена (winws)"
    except Exception:
        pass
    return False, "Служба не установлена"


def install_zapret_service(zapret_dir, preset_bat="general (ALT2).bat"):
    """Install Zapret as a background Windows Service so UAC is prompted ONLY ONCE."""
    import ctypes, subprocess
    if not zapret_dir or not os.path.exists(zapret_dir):
        return False, "Папка Запрета не найдена"

    service_bat = os.path.join(zapret_dir, "service.bat")
    if not os.path.exists(service_bat):
        service_bat = os.path.join(os.path.dirname(zapret_dir), "service.bat")

    if os.path.exists(service_bat):
        try:
            res = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f'/c "{service_bat}" install', os.path.dirname(service_bat), 1)
            if res > 32:
                return True, "Запрос UAC отправлен. Установка службы Запрета (без повторных запросов UAC)..."
        except Exception as e:
            return False, f"Ошибка вызова UAC: {e}"

    winws_bin = os.path.join(zapret_dir, "winws.exe")
    if not os.path.exists(winws_bin):
        winws_bin = os.path.join(zapret_dir, "bin", "winws.exe")

    if os.path.exists(winws_bin):
        try:
            res = ctypes.windll.shell32.ShellExecuteW(None, "runas", winws_bin, "--install-service", os.path.dirname(winws_bin), 0)
            if res > 32:
                return True, "Служба Запрета успешно установлена!"
        except Exception as e:
            return False, f"Ошибка: {e}"

    return False, "Не найден скрипт управления службой Запрета"


def remove_zapret_service(zapret_dir):
    """Remove Zapret Windows Service."""
    import ctypes
    if zapret_dir and os.path.exists(zapret_dir):
        service_bat = os.path.join(zapret_dir, "service.bat")
        if not os.path.exists(service_bat):
            service_bat = os.path.join(os.path.dirname(zapret_dir), "service.bat")

        if os.path.exists(service_bat):
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f'/c "{service_bat}" remove', os.path.dirname(service_bat), 1)
                return True, "Запрос UAC на удаление службы отправлен"
            except Exception as e:
                return False, str(e)

    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "sc", "delete zapret", "", 0)
        return True, "Запрос на удаление службы отправлен"
    except Exception as e:
        return False, str(e)


def get_latest_github_zapret_info():
    """
    Dynamically fetch the latest release tag and download URL from GitHub API.
    Supports multi-level fallback (Direct -> Local HTTP Proxy -> Local SOCKS Proxy).
    Returns (version_tag: str, download_url: str).
    """
    import requests
    api_url = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest"
    headers = {"User-Agent": "v2rayN/6.23 (Windows; GibVPN)"}

    proxy_options = [
        None,
        {"http": "http://127.0.0.1:10809", "https": "http://127.0.0.1:10809"},
        {"http": "socks5://127.0.0.1:10808", "https": "socks5://127.0.0.1:10808"}
    ]

    env_proxies = {k: os.environ.pop(k) for k in list(os.environ.keys()) if "proxy" in k.lower()}

    tag_name = None
    download_url = None

    for proxies in proxy_options:
        try:
            s = requests.Session()
            s.trust_env = False
            r = s.get(api_url, headers=headers, proxies=proxies, timeout=5)
            if r.status_code == 200:
                data = r.json()
                tag_name = data.get("tag_name", "").lstrip("v")
                for asset in data.get("assets", []):
                    name = asset.get("name", "").lower()
                    if name.endswith(".zip"):
                        download_url = asset.get("browser_download_url")
                        break
                if tag_name:
                    break
        except Exception:
            continue

    os.environ.update(env_proxies)

    if not tag_name:
        tag_name = "1.10.0"

    if not download_url:
        download_url = f"https://github.com/Flowseal/zapret-discord-youtube/releases/download/{tag_name}/zapret-discord-youtube-{tag_name}.zip"

    return tag_name, download_url


def download_zapret_github_update(zapret_dir, target_version=None):
    """
    Dynamically download and update Zapret engine to the latest GitHub release.
    Returns (success: bool, msg: str).
    """
    import requests, zipfile, io, shutil

    latest_tag, download_url = get_latest_github_zapret_info()
    version = target_version or latest_tag or "1.10.0"

    urls_to_try = []
    if download_url:
        urls_to_try.append(download_url)
    urls_to_try.append(f"https://github.com/Flowseal/zapret-discord-youtube/releases/download/{version}/zapret-discord-youtube-{version}.zip")
    urls_to_try.append(f"https://github.com/Flowseal/zapret-discord-youtube/archive/refs/tags/{version}.zip")

    headers = {"User-Agent": "v2rayN/6.23 (Windows; GibVPN)"}

    env_proxies = {k: os.environ.pop(k) for k in list(os.environ.keys()) if "proxy" in k.lower()}
    r = None
    last_err = None

    proxy_options = [
        None,
        {"http": "http://127.0.0.1:10809", "https": "http://127.0.0.1:10809"},
        {"http": "socks5://127.0.0.1:10808", "https": "socks5://127.0.0.1:10808"}
    ]

    for u in urls_to_try:
        for proxies in proxy_options:
            try:
                s = requests.Session()
                s.trust_env = False
                res = s.get(u, headers=headers, proxies=proxies, timeout=12)
                if res.status_code == 200 and len(res.content) > 1000:
                    r = res
                    break
            except Exception as e:
                last_err = str(e)
        if r and r.status_code == 200:
            break

    os.environ.update(env_proxies)

    if not r or r.status_code != 200:
        return False, f"Не удалось загрузить v{version} с GitHub: {last_err or 'Блокировка сети'}"

    try:
        z = zipfile.ZipFile(io.BytesIO(r.content))
        target_dir = zapret_dir or os.path.join(WORK_DIR, "zapret_bin")
        os.makedirs(target_dir, exist_ok=True)

        for member in z.infolist():
            filename = member.filename
            if "/" in filename:
                parts = filename.split("/")
                rel_path = "/".join(parts[1:])
            else:
                rel_path = filename
            if not rel_path:
                continue

            # Archives are external input.  Refuse traversal such as ../../x
            # even when a release mirror is compromised.
            dest_path = os.path.abspath(os.path.join(target_dir, rel_path))
            target_root = os.path.abspath(target_dir) + os.sep
            if not dest_path.startswith(target_root):
                raise ValueError(f"Недопустимый путь в архиве: {filename}")
            if member.is_dir():
                os.makedirs(dest_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with z.open(member) as source, open(dest_path, "wb") as target:
                    shutil.copyfileobj(source, target)

        return True, f"Запрет успешно обновлён до версии v{version} с GitHub!"
    except Exception as e:
        return False, f"Ошибка распаковки архива v{version}: {e}"


def emergency_fix_internet():
    """
    Emergency Network Recovery:
    1. Kills all orphaned xray, winws, v2ray processes.
    2. Stops Zapret and WinDivert services/drivers.
    3. Clears Windows System Proxy in Registry.
    4. Resets WINHTTP system proxy.
    5. Flushes Windows DNS Resolver cache.
    Returns (success: bool, log_lines: list[str]).
    """
    import subprocess, winreg
    log_lines = []

    # 1. Kill orphaned winws processes (Zapret)
    for proc_name in ["winws.exe"]:
        try:
            res = subprocess.run(["taskkill", "/F", "/IM", proc_name], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                log_lines.append(f"Остановлен процесс: {proc_name}")
        except Exception:
            pass

    # 2. Stop Zapret and WinDivert services/drivers
    for svc in ["zapret", "winws", "WinDivert", "WinDivert1.4"]:
        try:
            subprocess.run(["sc", "stop", svc], capture_output=True, text=True, timeout=2)
            subprocess.run(["net", "stop", svc], capture_output=True, text=True, timeout=2)
        except Exception:
            pass

    # 3. Clear System Proxy in Registry
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(key, "ProxyServer")
            except FileNotFoundError:
                pass
            try:
                winreg.DeleteValue(key, "ProxyOverride")
            except FileNotFoundError:
                pass
        log_lines.append("Системный прокси Windows отключён (Registry cleared)")
    except Exception as e:
        log_lines.append(f"Ошибка сброса прокси: {e}")

    # 4. Reset WINHTTP proxy
    try:
        subprocess.run(["netsh", "winhttp", "reset", "proxy"], capture_output=True, text=True, timeout=2)
        log_lines.append("Сброшен WINHTTP прокси (netsh winhttp reset proxy)")
    except Exception:
        pass

    # 5. Flush DNS Cache
    try:
        res = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            log_lines.append("Кэш DNS успешно очищен (ipconfig /flushdns)")
    except Exception:
        pass

    return True, log_lines


CURRENT_APP_VERSION = "3.0.5"


def get_latest_github_app_info(repo=None):
    """
    Check GitHub Releases for GibVPN updates.
    Tries Direct connection -> local HTTP proxy -> local SOCKS proxy.
    Returns (latest_version_str, download_url, release_notes_str).
    """
    import requests
    target_repo = repo or os.environ.get("GIBVPN_REPO", "ryoqe/gibvpn")
    api_url = f"https://api.github.com/repos/{target_repo}/releases/latest"
    headers = {"User-Agent": "GibVPN-Updater/3.0"}

    proxy_options = [
        None,
        {"http": "http://127.0.0.1:10809", "https": "http://127.0.0.1:10809"},
        {"http": "socks5://127.0.0.1:10808", "https": "socks5://127.0.0.1:10808"}
    ]

    env_proxies = {k: os.environ.pop(k) for k in list(os.environ.keys()) if "proxy" in k.lower()}

    tag_name = None
    download_url = None
    notes = ""

    for proxies in proxy_options:
        try:
            s = requests.Session()
            s.trust_env = False
            r = s.get(api_url, headers=headers, proxies=proxies, timeout=5)
            if r.status_code == 200:
                data = r.json()
                tag_name = data.get("tag_name", "").lstrip("v")
                notes = data.get("body", "")
                assets = data.get("assets", [])
                # The in-app updater replaces an executable. ZIP files remain
                # useful for manual downloads but must never be selected here.
                for asset in assets:
                    name = asset.get("name", "").lower()
                    if name.endswith(".exe"):
                        download_url = asset.get("browser_download_url")
                        break
                if tag_name:
                    break
        except Exception:
            continue

    os.environ.update(env_proxies)
    return tag_name, download_url, notes


def apply_downloaded_app_update(file_bytes, filename):
    """
    Save update payload and launch update script to overwrite current binary on exit.
    """
    import tempfile, subprocess
    if not filename.lower().endswith(".exe") or file_bytes[:2] != b"MZ":
        return False, "Обновление должно быть подписанным исполняемым файлом .exe"
    temp_dir = tempfile.mkdtemp(prefix="gibvpn_update_")
    dest_path = os.path.join(temp_dir, filename)
    with open(dest_path, "wb") as f:
        f.write(file_bytes)

    cur_exe = sys.executable
    if getattr(sys, 'frozen', False):
        bat_path = os.path.join(temp_dir, "update.bat")
        script = f"""@echo off
timeout /t 2 /nobreak > nul
copy /y "{dest_path}" "{cur_exe}"
start "" "{cur_exe}"
del "%~f0"
"""
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write(script)
        subprocess.Popen(["cmd.exe", "/c", bat_path], creationflags=0x08000000)
        return True, "Обновление скачано! Перезапуск приложения..."
    else:
        return True, f"Файл обновления сохранён в {dest_path}"
