param(
    [switch]$DryRun,
    [ValidateRange(30, 300)][int]$DurationSeconds = 120
)

$ErrorActionPreference = 'Stop'
$taskLogPath = Join-Path $PSScriptRoot 'steam_cloud_direct_test.log'
function Write-TestLog([string]$Message) {
    $taskLine = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $taskLogPath -Value $taskLine -Encoding utf8
    Write-Output $taskLine
}

# This diagnostic never stops Steam/VPN and never changes save files.
# Only temporary /32 routes are added; finally removes only routes we created.
$taskAdapter = Get-NetIPConfiguration -InterfaceIndex 10
if ($taskAdapter.InterfaceAlias -ne 'Ethernet' -or
    $taskAdapter.IPv4DefaultGateway.NextHop -ne '192.168.50.1') {
    throw 'Physical adapter changed; diagnostic aborted without adding routes.'
}
$taskHosts = @(
    'steamcloud-dub.s3.dualstack.eu-west-1.amazonaws.com',
    'steamcloud-frf.s3.dualstack.eu-central-1.amazonaws.com'
)
$taskAddresses = @(
    foreach ($taskHost in $taskHosts) {
        Resolve-DnsName -Name $taskHost -Type A -Server '192.168.50.1' -DnsOnly |
            Where-Object IPAddress | ForEach-Object IPAddress
    }
    # Include the addresses Steam already selected before DNS rotated.
    $taskSteam = Get-Process -Name steam -ErrorAction SilentlyContinue
    if ($taskSteam) {
        Get-NetTCPConnection -OwningProcess $taskSteam.Id -ErrorAction SilentlyContinue |
            Where-Object {
                $_.RemotePort -eq 443 -and
                $_.RemoteAddress -match '^(3\.5\.|52\.219\.|52\.92\.)'
            } | ForEach-Object RemoteAddress
    }
) | Sort-Object -Unique
if (!$taskAddresses -or $taskAddresses.Count -gt 40) {
    throw 'Unexpected endpoint count; diagnostic aborted without adding routes.'
}
foreach ($taskAddress in $taskAddresses) {
    $taskParsed = [System.Net.IPAddress]::Parse($taskAddress)
    if ($taskParsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $taskAddress -notmatch '^(3\.5\.|52\.219\.|52\.92\.)') {
        throw "Unexpected endpoint address '$taskAddress'; diagnostic aborted without adding routes."
    }
}
if ($DryRun) {
    Write-Output "DRY RUN: $($taskAddresses.Count) endpoint routes through Ethernet; no changes."
    exit 0
}
$taskPrincipal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (!$taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator permission is required to add temporary routes.'
}
$taskAdded = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($taskAddress in $taskAddresses) {
        $taskPrefix = "$taskAddress/32"
        $taskExisting = Get-NetRoute -DestinationPrefix $taskPrefix -InterfaceIndex 10 `
            -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        if ($taskExisting) { continue }
        $taskRoute = New-NetRoute -DestinationPrefix $taskPrefix -InterfaceIndex 10 `
            -NextHop '192.168.50.1' -RouteMetric 1 -PolicyStore ActiveStore
        $taskAdded.Add($taskRoute)
    }
    Write-TestLog "READY: $($taskAdded.Count) temporary routes. Retry Tavern Keeper cloud sync now."
    Start-Sleep -Seconds $DurationSeconds
}
catch {
    Write-TestLog "ERROR: $($_.Exception.Message)"
    throw
}
finally {
    $taskCleanupFailures = 0
    foreach ($taskRoute in $taskAdded) {
        try { $taskRoute | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
        catch {
            $taskCleanupFailures++
            Write-TestLog "CLEANUP ERROR: $($taskRoute.DestinationPrefix)"
        }
    }
    Write-TestLog "FINISHED: routes removed; cleanup failures=$taskCleanupFailures."
}
