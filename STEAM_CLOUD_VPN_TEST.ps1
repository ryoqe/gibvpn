param(
    [switch]$DryRun,
    [ValidateRange(30, 300)][int]$DurationSeconds = 240
)
$ErrorActionPreference = 'Stop'
$taskLogPath = Join-Path $PSScriptRoot 'steam_cloud_vpn_test.log'
function Write-TestLog([string]$Message) {
    $taskLine = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $taskLogPath -Value $taskLine -Encoding utf8
    Write-Output $taskLine
}
$taskBin = Join-Path $PSScriptRoot 'singbox_bin\sing-box-1.13.14-windows-amd64\sing-box.exe'
$taskDataDir = Join-Path $env:APPDATA 'GibVPN'
$taskLiveCfg = Get-Content -LiteralPath (Join-Path $taskDataDir 'config.json') -Raw | ConvertFrom-Json
$taskSocks = @($taskLiveCfg.inbounds | Where-Object tag -eq 'socks-in')
if ($taskSocks.Count -ne 1 -or $taskSocks[0].protocol -ne 'socks') {
    throw 'Expected live VPN SOCKS listener was not found.'
}
$taskSocket = [Net.Sockets.TcpClient]::new()
try { $taskSocket.Connect('127.0.0.1', [int]$taskSocks[0].port) }
finally { $taskSocket.Dispose() }
$taskRanges = Invoke-RestMethod -Uri 'https://ip-ranges.amazonaws.com/ip-ranges.json' -TimeoutSec 15
$taskPrefixes = @($taskRanges.prefixes | Where-Object {
    $_.service -eq 'S3' -and $_.region -in @('eu-west-1', 'eu-central-1')
} | ForEach-Object ip_prefix | Sort-Object -Unique)
if ($taskPrefixes.Count -lt 2 -or $taskPrefixes.Count -gt 80) { throw 'Unexpected AWS range count.' }
foreach ($taskPrefix in $taskPrefixes) {
    if ($taskPrefix -notmatch '^([0-9.]+)/([0-9]+)$' -or [int]$Matches[2] -lt 16) {
        throw 'Unexpected broad route; no changes made.'
    }
    $taskAddress = [Net.IPAddress]::Parse($Matches[1])
    if ($taskAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Expected IPv4 routes.'
    }
}
$taskInterface = 'gib-cloud-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$taskCfgPath = Join-Path $env:TEMP ($taskInterface + '.json')
$taskStdout = Join-Path $env:TEMP ($taskInterface + '.out.log')
$taskStderr = Join-Path $env:TEMP ($taskInterface + '.err.log')
$taskCfg = @{
    log = @{ level = 'warn' }
    dns = @{
        servers = @(@{ tag = 'vpn-dns'; type = 'tcp'; server = '1.1.1.1'; detour = 'cloud-vpn' })
        final = 'vpn-dns'; strategy = 'ipv4_only'
    }
    inbounds = @(@{
        type = 'tun'; tag = 'cloud-tun'; interface_name = $taskInterface
        address = @('172.30.252.1/30'); mtu = 1400
        auto_route = $false; strict_route = $false; stack = 'gvisor'
    })
    outbounds = @(@{
        type = 'socks'; tag = 'cloud-vpn'; server = '127.0.0.1'; server_port = [int]$taskSocks[0].port
    })
    route = @{
        auto_detect_interface = $true
        rules = @(@{ protocol = 'dns'; action = 'hijack-dns' })
        final = 'cloud-vpn'
    }
}
$taskCfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $taskCfgPath -Encoding utf8
$taskAdded = [System.Collections.Generic.List[object]]::new()
$taskChild = $null
try {
    & $taskBin check -c $taskCfgPath
    if ($LASTEXITCODE -ne 0) { throw 'Auxiliary engine configuration check failed.' }
    if ($DryRun) {
        Write-Output "DRY RUN: valid auxiliary config; $($taskPrefixes.Count) S3 ranges; no adapters or routes changed."
        return
    }
    $taskPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator permission is required for this temporary adapter.'
    }
    $taskChild = Start-Process -FilePath $taskBin -ArgumentList @('run', '-c', ('"{0}"' -f $taskCfgPath)) `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $taskStdout -RedirectStandardError $taskStderr
    $taskAdapter = $null
    for ($taskAttempt = 0; $taskAttempt -lt 40; $taskAttempt++) {
        if ($taskChild.HasExited) { throw 'Auxiliary engine exited before adapter creation.' }
        $taskAdapter = Get-NetAdapter -Name $taskInterface -ErrorAction SilentlyContinue
        if ($taskAdapter) { break }
        Start-Sleep -Milliseconds 250
    }
    if (!$taskAdapter) { throw 'Auxiliary adapter was not created.' }
    # auto_route=false must leave global DNS alone. Abort before adding routes if not.
    $taskDns = @(Get-DnsClientServerAddress -InterfaceIndex $taskAdapter.ifIndex -AddressFamily IPv4 |
        ForEach-Object ServerAddresses)
    if ($taskDns.Count) { throw 'Auxiliary adapter unexpectedly configured DNS; test aborted.' }
    foreach ($taskPrefix in $taskPrefixes) {
        $taskRoute = New-NetRoute -DestinationPrefix $taskPrefix -InterfaceIndex $taskAdapter.ifIndex `
            -NextHop '172.30.252.2' -RouteMetric 1 -PolicyStore ActiveStore
        $taskAdded.Add($taskRoute)
    }
    Write-TestLog "READY: auxiliary PID=$($taskChild.Id), adapter=$taskInterface, routes=$($taskAdded.Count). Retry Tavern Keeper cloud sync."
    $taskDeadline = (Get-Date).AddSeconds($DurationSeconds)
    while ((Get-Date) -lt $taskDeadline) {
        if ($taskChild.HasExited) { throw 'Auxiliary engine exited during test.' }
        Start-Sleep -Seconds 1
    }
}
catch {
    Write-TestLog "ERROR: $($_.Exception.Message)"
    throw
}
finally {
    $taskCleanupFailures = 0
    foreach ($taskRoute in $taskAdded) {
        try { $taskRoute | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
        catch { $taskCleanupFailures++; Write-TestLog "CLEANUP ERROR: $($taskRoute.DestinationPrefix)" }
    }
    # Terminate only the auxiliary child created above, never the live engines.
    if ($taskChild -and !$taskChild.HasExited) {
        Stop-Process -Id $taskChild.Id -Force -ErrorAction SilentlyContinue
    }
    if (!$DryRun) { Write-TestLog "FINISHED: cleanup failures=$taskCleanupFailures; live VPN and Steam untouched." }
    if (Test-Path -LiteralPath $taskCfgPath) { Remove-Item -LiteralPath $taskCfgPath -Force }
}
