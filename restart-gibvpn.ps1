# Перезапуск GibVPN из исходников с правами администратора (без консольного окна).
# Запускать: Start-Process powershell -Verb RunAs -ArgumentList '-File', '<путь к скрипту>'
$ErrorActionPreference = "SilentlyContinue"

# 1. Убить только процессы GUI GibVPN из исходников (по командной строке)
Get-CimInstance Win32_Process -Filter "Name='python.exe' or Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like "*gibvpn*gui.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Start-Sleep -Seconds 2

# 2. Поднять заново через pythonw (оконный режим, консоль не появляется),
#    UTF-8 на всякий случай для файловых потоков.
$env:PYTHONUTF8 = "1"
Start-Process -FilePath "C:\Users\merka\gibvpn\venv\Scripts\pythonw.exe" `
    -ArgumentList "`"C:\Users\merka\gibvpn\gui.py`"" `
    -WorkingDirectory "C:\Users\merka\gibvpn"

Write-Output "GibVPN restarted (windowed)"
