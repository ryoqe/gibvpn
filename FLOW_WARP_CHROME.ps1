# Start a separate Chrome profile; leave the existing VPN and browser settings alone.
$ErrorActionPreference = 'Stop'
$vpnDataFolder = Join-Path $env:APPDATA 'GibVPN'
$vpnConfigFile = Join-Path $vpnDataFolder 'config.json'
if (-not (Test-Path -LiteralPath $vpnConfigFile)) {
    throw 'Сначала подключите GibVPN.'
}
$vpnRuntimeConfig = Get-Content -LiteralPath $vpnConfigFile -Raw | ConvertFrom-Json
if (-not ($vpnRuntimeConfig.outbounds | Where-Object { $_.tag -eq 'warp-proxy' })) {
    throw 'В активном VPN нет WARP. Включите WARP перед проверкой.'
}
$browserProxyInbound = $vpnRuntimeConfig.inbounds | Where-Object { $_.tag -eq 'warp-http-in' } | Select-Object -First 1
if (-not $browserProxyInbound) { throw 'Не найден отдельный WARP-прокси.' }
$browserProxyPort = [int]$browserProxyInbound.port
$proxySocket = [System.Net.Sockets.TcpClient]::new()
try {
    if (-not $proxySocket.ConnectAsync('127.0.0.1', $browserProxyPort).Wait(2000)) {
        throw 'WARP-прокси не отвечает. Проверьте подключение GibVPN.'
    }
} finally { $proxySocket.Dispose() }
$chromeExecutable = @(
    (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
    (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $chromeExecutable) { throw 'Google Chrome не установлен.' }
$flowBrowserProfile = Join-Path $env:LOCALAPPDATA 'GibVPN\FlowChromeWARP'
$chromeArguments = @(
    ('--user-data-dir="{0}"' -f $flowBrowserProfile),
    ('--proxy-server=http://127.0.0.1:{0}' -f $browserProxyPort),
    '--proxy-bypass-list=<-loopback>',
    '--disable-quic',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--no-first-run',
    '--no-default-browser-check',
    '--new-window',
    'https://flow.google.com/'
)
# This is an interactive browser used for the requested Flow check.
Start-Process -FilePath $chromeExecutable -ArgumentList $chromeArguments
Write-Output ('Chrome открыт через WARP-прокси 127.0.0.1:{0}. Войдите в Google и откройте сам Flow.' -f $browserProxyPort)
