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
import hashlib

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
        base_src = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base_src = os.path.dirname(os.path.abspath(__file__))

    # Seed initial user configuration files if not present in APPDATA
    for item in ("app_settings.json", "direct_domains.txt", "direct_apps.txt", "vpn_apps.txt", "warp_domains.txt", "assets", "singbox_bin"):
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


def _copy_if_changed(src, dst):
    """Atomically refresh an embedded helper while preserving equal files."""
    if not os.path.isfile(src):
        return
    try:
        if os.path.isfile(dst) and os.path.getsize(src) == os.path.getsize(dst):
            def digest(path):
                value = hashlib.sha256()
                with open(path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        value.update(chunk)
                return value.digest()
            if digest(src) == digest(dst):
                return
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        temp_path = dst + ".new"
        shutil.copy2(src, temp_path)
        os.replace(temp_path, dst)
    except OSError:
        # If security software locks an old helper, keep the usable copy and
        # retry automatically on the next launch.
        try:
            os.remove(dst + ".new")
        except OSError:
            pass


def _sync_embedded_tree(src_root, dst_root):
    if not os.path.isdir(src_root):
        return
    for root, _dirs, files in os.walk(src_root):
        relative = os.path.relpath(root, src_root)
        target_root = dst_root if relative == "." else os.path.join(dst_root, relative)
        for filename in files:
            _copy_if_changed(
                os.path.join(root, filename),
                os.path.join(target_root, filename),
            )


def get_work_dir(app_dir):
    """
    Directory that contains xray.exe and helper data files.
    When helpers already live next to the executable (or when running from
    source), this is the same as app_dir. In a PyInstaller onefile bundle the
    helpers are unpacked into a temporary _MEIPASS directory; copy them to
    app_dir once so they (and the settings/config written alongside them)
    persist across restarts.
    """
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass and os.path.exists(os.path.join(meipass, "xray.exe")):
        immutable_helpers = [
            'xray.exe', 'geoip.dat', 'geosite.dat',
            'ofont.ru_Zeequada.ttf',
        ]
        for name in immutable_helpers:
            src = os.path.join(meipass, name)
            dst = os.path.join(app_dir, name)
            _copy_if_changed(src, dst)

        # User-editable rules are initial defaults, never overwrite them.
        for name in ('direct_domains.txt', 'direct_apps.txt', 'vpn_apps.txt', 'warp_domains.txt'):
            src = os.path.join(meipass, name)
            dst = os.path.join(app_dir, name)
            if os.path.isfile(src) and not os.path.exists(dst):
                _copy_if_changed(src, dst)

        # Refresh bundled engines/assets recursively. Private WARP profiles and
        # subscription caches are deliberately never embedded or overwritten.
        for dirname in ('singbox_bin', 'zapret_bin', 'assets'):
            _sync_embedded_tree(
                os.path.join(meipass, dirname),
                os.path.join(app_dir, dirname),
            )

        if os.path.exists(os.path.join(app_dir, "xray.exe")):
            return app_dir

        # If copying failed for some reason, fall back to the temp dir so the
        # app can at least start.
        return meipass

    if os.path.exists(os.path.join(app_dir, "xray.exe")):
        return app_dir

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


def restart_as_windows_admin(extra_args=None):
    """Launch this application through UAC and return whether it was accepted.

    The current process is deliberately not terminated here.  The GUI closes
    itself only after ShellExecute reports a successful launch, so cancelling
    the UAC prompt cannot make the application disappear.
    """
    if os.name != "nt":
        return False

    import ctypes
    import subprocess

    executable = sys.executable
    if getattr(sys, "frozen", False):
        arguments = list(sys.argv[1:])
    else:
        arguments = [os.path.abspath(sys.argv[0]), *sys.argv[1:]]
    for argument in extra_args or ():
        if argument not in arguments:
            arguments.append(argument)

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        subprocess.list2cmdline(arguments),
        os.getcwd(),
        1,
    )
    return int(result) > 32


def find_conflicting_vpn_adapters():
    """Return active third-party VPN adapters that currently own full routes.

    Two full-tunnel clients cannot safely manage the same Windows default
    routes.  Detect that situation before sing-box changes anything so a failed
    launch cannot take the whole machine offline.
    """
    if os.name != "nt":
        return []

    import json
    import subprocess

    script = r"""
$fullPrefixes = @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1')
$routeIndexes = @(Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $fullPrefixes -contains $_.DestinationPrefix } |
    Select-Object -ExpandProperty InterfaceIndex -Unique)
@(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Status -eq 'Up' -and
        $routeIndexes -contains $_.InterfaceIndex -and
        $_.Name -ne 'gibvpn-tun' -and
        (($_.Name + ' ' + $_.InterfaceDescription) -match '(?i)(tun|tap|wintun|wireguard|warp|happ|tailscale|openvpn)')
    } |
    Select-Object Name, InterfaceDescription) | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        names = []
        for item in data:
            name = str(item.get("Name", "")).strip()
            if name and name not in names:
                names.append(name)
        return names
    except (OSError, ValueError, subprocess.SubprocessError):
        # Detection is a safety aid. A locked-down PowerShell policy must not
        # make the ordinary proxy mode unusable.
        return []


def wait_for_local_port(port, host="127.0.0.1", timeout=5.0):
    """Wait until a local helper has actually opened its listening socket."""
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def find_free_local_port_block():
    """Reserve a collision-free Xray listener block without killing other VPNs."""
    import socket

    for base in (10808, 11808, 12808, 13808, 20808, 21808, 30808):
        ports = (base, base + 1, base + 2, base + 3, base + 77)
        sockets = []
        try:
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(sock)
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind(("127.0.0.1", port))
            return base
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("Не найден свободный набор локальных портов для Xray")


def verify_tun_connectivity(timeout=8):
    """Probe the new system route from a child process captured by the TUN."""
    import subprocess

    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        return True, "curl недоступен, проверка пропущена"

    targets = (
        "https://cp.cloudflare.com/generate_204",
        "https://www.google.com/generate_204",
    )
    errors = []
    for url in targets:
        try:
            result = subprocess.run(
                [
                    curl, "--noproxy", "*", "--silent", "--show-error",
                    "--output", os.devnull, "--write-out", "%{http_code}",
                    "--connect-timeout", "7", "--max-time", str(timeout), url,
                ],
                capture_output=True,
                text=True,
                timeout=timeout + 2,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            code = result.stdout.strip()
            if result.returncode == 0 and code in {"200", "204"}:
                return True, f"{url}: HTTP {code}"
            errors.append((result.stderr or f"HTTP {code}").strip())
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    return False, "; ".join(error for error in errors if error) or "нет ответа"


_KILL_JOB_HANDLE = None


def attach_process_to_app_job(proc):
    """Ensure a helper is killed by Windows if GibVPN crashes or is updated."""
    if os.name != "nt" or proc is None or not hasattr(proc, "_handle"):
        return True

    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    global _KILL_JOB_HANDLE
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

    if not _KILL_JOB_HANDLE:
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return False
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle, 9, ctypes.byref(info), ctypes.sizeof(info)
        ):
            kernel32.CloseHandle(handle)
            return False
        _KILL_JOB_HANDLE = handle

    return bool(kernel32.AssignProcessToJobObject(
        _KILL_JOB_HANDLE, wintypes.HANDLE(int(proc._handle))
    ))


APP_DIR = get_app_dir()
WORK_DIR = get_work_dir(APP_DIR)

# Only these per-user Internet Settings values are touched by the optional
# system-proxy mode.  WinHTTP is deliberately never changed.
SYSTEM_PROXY_VALUES = (
    "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect",
)
SYSTEM_PROXY_BACKUP_PATH = os.path.join(APP_DIR, "system_proxy_backup.json")
ENVIRONMENT_PROXY_VALUES = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")
ENVIRONMENT_PROXY_BACKUP_PATH = os.path.join(APP_DIR, "environment_proxy_backup.json")
LOCAL_HTTP_PROXY_URL = "http://127.0.0.1:10809"
LOCAL_ANTIGRAVITY_PROXY_URL = "http://127.0.0.1:10811"
ANTIGRAVITY_PROXY_BACKUP_PATH = os.path.join(APP_DIR, "antigravity_proxy_backup.json")
ANTIGRAVITY_SETTINGS_PATH = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "Antigravity", "User", "settings.json",
)


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


def configure_local_proxy_ports(base_port):
    global LOCAL_HTTP_PROXY_URL, LOCAL_ANTIGRAVITY_PROXY_URL
    LOCAL_HTTP_PROXY_URL = f"http://127.0.0.1:{int(base_port) + 1}"
    LOCAL_ANTIGRAVITY_PROXY_URL = f"http://127.0.0.1:{int(base_port) + 3}"


def _is_gibvpn_local_proxy(value, offsets=(1, 3)):
    """Recognize a proxy from any port block used by an earlier run."""
    text = str(value or "").removeprefix("http://")
    if not text.startswith("127.0.0.1:"):
        return False
    try:
        port = int(text.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return False
    bases = (10808, 11808, 12808, 13808, 20808, 21808, 30808)
    return any(port == base + offset for base in bases for offset in offsets)


def enable_windows_system_proxy(server=None):
    """Enable a user-level Windows proxy and return its restorable old state."""
    import winreg
    server = server or LOCAL_HTTP_PROXY_URL.removeprefix("http://")
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
        is_ours = (
            current.get("ProxyEnable", {}).get("value") == 1
            and _is_gibvpn_local_proxy(
                current.get("ProxyServer", {}).get("value"), offsets=(1,)
            )
        )
        if is_ours:
            restore_windows_system_proxy(snapshot)
        clear_windows_system_proxy_backup()
        return is_ours
    except (OSError, ValueError):
        return False


def _broadcast_environment_change():
    r"""Tell newly launched desktop applications that HKCU\Environment changed."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes
        result = wintypes.DWORD()
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x001A, 0, ctypes.c_wchar_p("Environment"), 0x0002, 2000,
            ctypes.byref(result),
        )
    except Exception:
        pass


def read_user_environment_proxy():
    """Snapshot proxy-related user environment values, preserving their types."""
    import winreg
    snapshot = {}
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ,
        )
    except FileNotFoundError:
        return {name: {"exists": False} for name in ENVIRONMENT_PROXY_VALUES}
    with key:
        for name in ENVIRONMENT_PROXY_VALUES:
            try:
                value, value_type = winreg.QueryValueEx(key, name)
                snapshot[name] = {
                    "exists": True, "value": value, "type": value_type,
                }
            except FileNotFoundError:
                snapshot[name] = {"exists": False}
    return snapshot


def restore_user_environment_proxy(snapshot):
    """Restore environment proxy values without touching unrelated variables."""
    import winreg
    if not snapshot:
        return
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE,
    ) as key:
        for name in ENVIRONMENT_PROXY_VALUES:
            item = snapshot.get(name, {"exists": False})
            if item.get("exists"):
                winreg.SetValueEx(key, name, 0, item["type"], item["value"])
                os.environ[name] = str(item["value"])
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
                os.environ.pop(name, None)
    _broadcast_environment_change()


def enable_user_environment_proxy(proxy_url=None):
    """Cover apps (including Antigravity) that ignore Windows Internet Settings."""
    import winreg
    proxy_url = proxy_url or LOCAL_HTTP_PROXY_URL
    snapshot = read_user_environment_proxy()
    previous_no_proxy = str(snapshot.get("NO_PROXY", {}).get("value", "") or "")
    exclusions = [part.strip() for part in previous_no_proxy.split(",") if part.strip()]
    exclusion_keys = {item.lower() for item in exclusions}
    for local_host in ("localhost", "127.0.0.1", "::1"):
        if local_host.lower() not in exclusion_keys:
            exclusions.append(local_host)
            exclusion_keys.add(local_host.lower())
    no_proxy = ",".join(exclusions)
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "HTTP_PROXY", 0, winreg.REG_SZ, proxy_url)
        winreg.SetValueEx(key, "HTTPS_PROXY", 0, winreg.REG_SZ, proxy_url)
        winreg.SetValueEx(key, "NO_PROXY", 0, winreg.REG_SZ, no_proxy)
    os.environ["HTTP_PROXY"] = proxy_url
    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["NO_PROXY"] = no_proxy
    _broadcast_environment_change()
    return snapshot


def save_user_environment_proxy_backup(snapshot):
    import json
    temp_path = ENVIRONMENT_PROXY_BACKUP_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle)
    os.replace(temp_path, ENVIRONMENT_PROXY_BACKUP_PATH)


def clear_user_environment_proxy_backup():
    try:
        os.remove(ENVIRONMENT_PROXY_BACKUP_PATH)
    except FileNotFoundError:
        pass


def recover_user_environment_proxy():
    """Recover only environment values that still point to GibVPN itself."""
    import json
    if not os.path.exists(ENVIRONMENT_PROXY_BACKUP_PATH):
        return False
    try:
        with open(ENVIRONMENT_PROXY_BACKUP_PATH, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
        current = read_user_environment_proxy()
        is_ours = all(
            _is_gibvpn_local_proxy(current.get(name, {}).get("value"), offsets=(1,))
            for name in ("HTTP_PROXY", "HTTPS_PROXY")
        )
        if is_ours:
            restore_user_environment_proxy(snapshot)
        clear_user_environment_proxy_backup()
        return is_ours
    except (OSError, ValueError):
        return False


def enable_antigravity_proxy(proxy_url=None):
    """Set Antigravity's explicit backend proxy while preserving user settings.

    Its model language server does not consistently inherit Explorer's updated
    environment or the Windows Chromium proxy.  The editor-level ``http.proxy``
    value is consumed by that backend and is therefore required in proxy mode.
    """
    import json
    proxy_url = proxy_url or LOCAL_ANTIGRAVITY_PROXY_URL

    settings_dir = os.path.dirname(ANTIGRAVITY_SETTINGS_PATH)
    if not os.path.isdir(os.path.dirname(settings_dir)):
        return False
    os.makedirs(settings_dir, exist_ok=True)
    try:
        if os.path.exists(ANTIGRAVITY_SETTINGS_PATH):
            with open(ANTIGRAVITY_SETTINGS_PATH, "r", encoding="utf-8-sig") as handle:
                settings = json.load(handle)
        else:
            settings = {}
        if not isinstance(settings, dict):
            return False

        if not os.path.exists(ANTIGRAVITY_PROXY_BACKUP_PATH):
            snapshot = {}
            for name in ("http.proxy", "http.proxySupport"):
                snapshot[name] = (
                    {"exists": True, "value": settings[name]}
                    if name in settings else {"exists": False}
                )
            temp_backup = ANTIGRAVITY_PROXY_BACKUP_PATH + ".tmp"
            with open(temp_backup, "w", encoding="utf-8") as handle:
                json.dump(snapshot, handle, ensure_ascii=False, indent=2)
            os.replace(temp_backup, ANTIGRAVITY_PROXY_BACKUP_PATH)

        settings["http.proxy"] = proxy_url
        settings["http.proxySupport"] = "override"
        temp_settings = ANTIGRAVITY_SETTINGS_PATH + ".tmp"
        with open(temp_settings, "w", encoding="utf-8") as handle:
            json.dump(settings, handle, ensure_ascii=False, indent=4)
            handle.write("\n")
        os.replace(temp_settings, ANTIGRAVITY_SETTINGS_PATH)
        return True
    except (OSError, ValueError, TypeError):
        return False


def recover_antigravity_proxy():
    """Restore Antigravity proxy keys if they are still managed by GibVPN."""
    import json

    if not os.path.exists(ANTIGRAVITY_PROXY_BACKUP_PATH):
        return False
    restored = False
    try:
        with open(ANTIGRAVITY_PROXY_BACKUP_PATH, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
        with open(ANTIGRAVITY_SETTINGS_PATH, "r", encoding="utf-8-sig") as handle:
            settings = json.load(handle)
        if (isinstance(settings, dict) and
                _is_gibvpn_local_proxy(settings.get("http.proxy"))):
            for name in ("http.proxy", "http.proxySupport"):
                item = snapshot.get(name, {"exists": False})
                if item.get("exists"):
                    settings[name] = item.get("value")
                else:
                    settings.pop(name, None)
            temp_settings = ANTIGRAVITY_SETTINGS_PATH + ".tmp"
            with open(temp_settings, "w", encoding="utf-8") as handle:
                json.dump(settings, handle, ensure_ascii=False, indent=4)
                handle.write("\n")
            os.replace(temp_settings, ANTIGRAVITY_SETTINGS_PATH)
            restored = True
    except (OSError, ValueError, TypeError):
        pass
    finally:
        try:
            os.remove(ANTIGRAVITY_PROXY_BACKUP_PATH)
        except FileNotFoundError:
            pass
    return restored

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
        attach_process_to_app_job(proc)
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
    """Stop only the Zapret process tree started by this application."""
    if proc is None or isinstance(proc, str):
        return
    try:
        import subprocess
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            timeout=2,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        proc.wait(timeout=0.5)
    except Exception:
        terminate_process(proc, timeout=0.5)


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
        {"http": LOCAL_HTTP_PROXY_URL, "https": LOCAL_HTTP_PROXY_URL},
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
        {"http": LOCAL_HTTP_PROXY_URL, "https": LOCAL_HTTP_PROXY_URL},
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
    1. Stops only GibVPN-managed services/drivers.
    2. Clears Windows System Proxy in Registry.
    3. Resets WINHTTP system proxy.
    4. Flushes Windows DNS Resolver cache.
    Returns (success: bool, log_lines: list[str]).
    """
    import subprocess, winreg
    log_lines = []

    if recover_user_environment_proxy():
        log_lines.append("Восстановлены переменные прокси приложений GibVPN")
    if recover_antigravity_proxy():
        log_lines.append("Восстановлены настройки прокси Antigravity")

    # Do not kill every winws.exe on the computer: it may belong to another
    # application. New GibVPN helpers are tied to the app's Windows Job Object.
    # Stop only the service names explicitly managed by GibVPN/Zapret.
    for svc in ["zapret", "winws", "WinDivert", "WinDivert1.4"]:
        try:
            subprocess.run(["sc", "stop", svc], capture_output=True, text=True, timeout=2)
            subprocess.run(["net", "stop", svc], capture_output=True, text=True, timeout=2)
        except Exception:
            pass

    # Clear System Proxy in Registry
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

    # Reset WINHTTP proxy
    try:
        subprocess.run(["netsh", "winhttp", "reset", "proxy"], capture_output=True, text=True, timeout=2)
        log_lines.append("Сброшен WINHTTP прокси (netsh winhttp reset proxy)")
    except Exception:
        pass

    # Flush DNS Cache
    try:
        res = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            log_lines.append("Кэш DNS успешно очищен (ipconfig /flushdns)")
    except Exception:
        pass

    return True, log_lines


CURRENT_APP_VERSION = "3.0.24"


def is_newer_version(candidate, current):
    """Compare dotted numeric versions without treating older tags as updates."""
    def parts(value):
        numbers = []
        for item in str(value or "").lstrip("vV").split("."):
            try:
                numbers.append(int(item))
            except ValueError:
                numbers.append(0)
        return tuple((numbers + [0, 0, 0, 0])[:4])
    return parts(candidate) > parts(current)


def get_latest_github_app_info(repo=None):
    """
    Check GitHub Releases for GibVPN updates.
    Tries Direct connection -> local HTTP proxy -> local SOCKS proxy.
    Returns (version, asset_api_url, notes, sha256, byte_size).
    """
    import requests
    target_repo = repo or os.environ.get("GIBVPN_REPO", "ryoqe/gibvpn")
    api_url = f"https://api.github.com/repos/{target_repo}/releases/latest"
    headers = {"User-Agent": "GibVPN-Updater/3.0"}

    proxy_options = [
        None,
        {"http": LOCAL_HTTP_PROXY_URL, "https": LOCAL_HTTP_PROXY_URL},
    ]

    env_proxies = {k: os.environ.pop(k) for k in list(os.environ.keys()) if "proxy" in k.lower()}

    tag_name = None
    download_url = None
    download_sha256 = None
    download_size = None
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
                        # The asset API is reachable anywhere release metadata
                        # is reachable and redirects to the same signed blob.
                        # It is more reliable than opening github.com/releases
                        # separately on filtered networks.
                        download_url = (
                            asset.get("url")
                            or asset.get("browser_download_url")
                        )
                        digest = str(asset.get("digest") or "")
                        if digest.lower().startswith("sha256:"):
                            download_sha256 = digest.split(":", 1)[1].lower()
                        try:
                            download_size = int(asset.get("size") or 0) or None
                        except (TypeError, ValueError):
                            download_size = None
                        break
                if tag_name:
                    break
        except Exception:
            continue

    os.environ.update(env_proxies)
    return tag_name, download_url, notes, download_sha256, download_size


def download_github_app_asset(
    download_url, expected_size, chunk_size=8 * 1024 * 1024
):
    """Download a GitHub release asset in resumable ranges.

    Large single responses can stall indefinitely on filtered networks. Each
    range is independently retried through direct, HTTP-proxy and SOCKS paths.
    Returns (success, path_or_error).
    """
    import requests
    import tempfile

    if not download_url or not expected_size:
        return False, "GitHub не сообщил URL или размер файла обновления"

    fd, temp_path = tempfile.mkstemp(prefix="gibvpn_asset_", suffix=".exe")
    os.close(fd)
    headers_base = {
        "User-Agent": "GibVPN-Updater/3.0",
        "Accept": "application/octet-stream",
    }
    proxy_options = [
        None,
        {"http": LOCAL_HTTP_PROXY_URL, "https": LOCAL_HTTP_PROXY_URL},
    ]

    try:
        with open(temp_path, "wb") as target:
            start = 0
            while start < expected_size:
                end = min(start + chunk_size - 1, expected_size - 1)
                received = None
                last_error = ""
                for proxies in proxy_options:
                    for _attempt in range(2):
                        try:
                            session = requests.Session()
                            session.trust_env = False
                            headers = dict(headers_base)
                            headers["Range"] = f"bytes={start}-{end}"
                            response = session.get(
                                download_url,
                                headers=headers,
                                proxies=proxies,
                                timeout=(12, 60),
                            )
                            expected_chunk = end - start + 1
                            if (
                                response.status_code == 206
                                and len(response.content) == expected_chunk
                            ):
                                received = response.content
                                break
                            if (
                                start == 0
                                and response.status_code == 200
                                and len(response.content) == expected_size
                            ):
                                received = response.content
                                end = expected_size - 1
                                break
                            last_error = (
                                f"HTTP {response.status_code}, "
                                f"получено {len(response.content)} байт"
                            )
                        except requests.RequestException as exc:
                            last_error = str(exc)
                    if received is not None:
                        break
                if received is None:
                    raise OSError(
                        f"Не удалось скачать блок {start}-{end}: {last_error}"
                    )
                target.write(received)
                start = end + 1

        if os.path.getsize(temp_path) != expected_size:
            raise OSError("Размер скачанного обновления не совпадает")
        return True, temp_path
    except OSError as exc:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        return False, str(exc)


def _schedule_app_update(dest_path, filename, restart_vpn=False):
    """Launch a detached updater that survives the GUI and one-file parent."""
    cur_exe = sys.executable
    if getattr(sys, 'frozen', False):
        import subprocess
        update_dir = os.path.dirname(dest_path)
        script_path = os.path.join(update_dir, "apply_update.ps1")
        status_path = os.path.join(APP_DIR, "update_status.log")
        restart_line = (
            f'Start-Process -FilePath "{cur_exe}" -ArgumentList "--start-vpn"'
            if restart_vpn else f'Start-Process -FilePath "{cur_exe}"'
        )
        script = f'''$ErrorActionPreference = "Stop"
$sourceExe = "{dest_path}"
$installedExe = "{cur_exe}"
$statusFile = "{status_path}"
$copied = $false
try {{
    for ($attempt = 0; $attempt -lt 120; $attempt++) {{
        Start-Sleep -Milliseconds 500
        try {{
            Copy-Item -LiteralPath $sourceExe -Destination $installedExe -Force
            if ((Get-FileHash -LiteralPath $sourceExe -Algorithm SHA256).Hash -ne
                (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash) {{
                throw "Hash mismatch after replacement"
            }}
            $copied = $true
            break
        }} catch {{
            if ($attempt -eq 119) {{ throw }}
        }}
    }}
    if (-not $copied) {{ throw "The old executable remained locked" }}
    {restart_line}
    Set-Content -LiteralPath $statusFile -Value "OK" -Encoding UTF8
    Remove-Item -LiteralPath $sourceExe -Force -ErrorAction SilentlyContinue
}} catch {{
    Set-Content -LiteralPath $statusFile -Value ("ERROR: " + $_.Exception.Message) -Encoding UTF8
}}
'''
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        creationflags = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
        command = [
            "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass", "-File", script_path,
        ]
        launch_options = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
        }
        try:
            # Escape a parent job when the launcher permits breakaway. This is
            # important for packaged apps and managed desktop environments.
            subprocess.Popen(
                command,
                creationflags=creationflags | 0x01000000,
                **launch_options,
            )
        except OSError:
            subprocess.Popen(
                command, creationflags=creationflags, **launch_options,
            )
        return True, "Обновление скачано! Перезапуск приложения..."
    return True, f"Файл обновления сохранён в {dest_path}"


def apply_downloaded_app_update_path(
    file_path, filename, expected_sha256=None, restart_vpn=False,
):
    """Verify a downloaded EXE by SHA-256 and schedule atomic replacement."""
    if not filename.lower().endswith(".exe"):
        return False, "Обновление должно быть исполняемым файлом .exe"
    try:
        with open(file_path, "rb") as source:
            if source.read(2) != b"MZ":
                return False, "Файл обновления не является Windows EXE"
            digest = hashlib.sha256()
            source.seek(0)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        return False, f"Не удалось прочитать обновление: {exc}"

    if not expected_sha256:
        return False, "GitHub не предоставил SHA-256 обновления; установка отменена"
    if digest.hexdigest().lower() != expected_sha256.lower():
        return False, "SHA-256 обновления не совпадает; файл удалён"

    update_dir = os.path.join(APP_DIR, ".updates")
    os.makedirs(update_dir, exist_ok=True)
    dest_path = os.path.join(update_dir, filename + ".new")
    try:
        shutil.copy2(file_path, dest_path)
    except OSError as exc:
        return False, f"Не удалось подготовить обновление: {exc}"
    return _schedule_app_update(dest_path, filename, restart_vpn=restart_vpn)


def apply_downloaded_app_update(file_bytes, filename, expected_sha256=None):
    """
    Save update payload and launch update script to overwrite current binary on exit.
    """
    import tempfile
    if not filename.lower().endswith(".exe") or file_bytes[:2] != b"MZ":
        return False, "Обновление должно быть исполняемым файлом .exe"
    if not expected_sha256:
        return False, "GitHub не предоставил SHA-256 обновления; установка отменена"
    actual_sha256 = hashlib.sha256(file_bytes).hexdigest()
    if actual_sha256.lower() != expected_sha256.lower():
        return False, "SHA-256 обновления не совпадает; файл удалён"
    temp_dir = tempfile.mkdtemp(prefix="gibvpn_update_")
    dest_path = os.path.join(temp_dir, filename)
    with open(dest_path, "wb") as f:
        f.write(file_bytes)

    return _schedule_app_update(dest_path, filename)
