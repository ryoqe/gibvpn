# Перезапуск GibVPN из исходников с правами администратора.
# Запускать: Start-Process powershell -Verb RunAs -ArgumentList '-File', '<путь к скрипту>'
$ErrorActionPreference = "SilentlyContinue"

# 1. Убить только процессы GUI GibVPN из исходников (по командной строке)
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like "*gibvpn*gui.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Start-Sleep -Seconds 2

# 2. Поднять заново (этот скрипт уже выполняется elevated)
Start-Process -FilePath "C:\Users\merka\gibvpn\venv\Scripts\python.exe" `
    -ArgumentList "`"C:\Users\merka\gibvpn\gui.py`"" `
    -WorkingDirectory "C:\Users\merka\gibvpn"

Write-Output "GibVPN restarted"
