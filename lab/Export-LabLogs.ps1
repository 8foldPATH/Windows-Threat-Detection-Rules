<#
.SYNOPSIS
    Exports recent lab event logs to .evtx files and copies them to the Mac.

.DESCRIPTION
    Exports the last N minutes of the six event logs the detections use into
    C:\lab\exports\<timestamp>\, then copies that folder, plus any telemetry-check CSVs,
    to the Mac through the folder shared in Windows App (\\tsclient\wtdl-transfer).

    Logs exported (one .evtx file each):
      Sysmon, Security, System, PowerShell, Defender, TaskScheduler

    Raw .evtx files contain host and account names, so they are never committed to Git
    (.gitignore excludes *.evtx). Only cleaned, single test events go into the repo.

.PARAMETER Minutes
    How far back to export. Default: 60.

.PARAMETER Destination
    Where to copy the export. Default: \\tsclient\wtdl-transfer, the Mac folder shared in Windows App.

.EXAMPLE
    & C:\lab\Export-LabLogs.ps1
    & C:\lab\Export-LabLogs.ps1 -Minutes 15
#>
#Requires -RunAsAdministrator
param(
    [int]    $Minutes     = 60,
    [string] $Destination = '\\tsclient\wtdl-transfer'
)
$ErrorActionPreference = 'Stop'

$logs = [ordered]@{
    'Sysmon'        = 'Microsoft-Windows-Sysmon/Operational'
    'Security'      = 'Security'
    'System'        = 'System'
    'PowerShell'    = 'Microsoft-Windows-PowerShell/Operational'
    'Defender'      = 'Microsoft-Windows-Windows Defender/Operational'
    'TaskScheduler' = 'Microsoft-Windows-TaskScheduler/Operational'
}

$stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$exportDir = Join-Path -Path 'C:\lab\exports' -ChildPath $stamp
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

# Only events from the last $Minutes minutes (timediff is in milliseconds).
$milliseconds = $Minutes * 60 * 1000
$query = "*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"

foreach ($name in $logs.Keys) {
    $file = Join-Path -Path $exportDir -ChildPath "$name.evtx"
    # Export to a local folder first and copy afterwards; exporting straight to a redirected folder is unreliable.
    wevtutil.exe export-log $logs[$name] $file "/query:$query"
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed to export '$($logs[$name])'" }
}

Write-Host "Exported the last $Minutes minutes to $exportDir" -ForegroundColor Cyan
Get-ChildItem -Path $exportDir |
    Format-Table -AutoSize -Property Name, @{ Name = 'SizeKB'; Expression = { [math]::Round($_.Length / 1KB) } }

if (Test-Path -Path $Destination) {
    Copy-Item -Path $exportDir -Destination $Destination -Recurse -Force
    Get-ChildItem -Path 'C:\lab' -Filter 'telemetry-check-*.csv' | Copy-Item -Destination $Destination -Force
    Write-Host "Copied to $Destination\$stamp" -ForegroundColor Green
}
else {
    Write-Host "Shared folder $Destination not found, so nothing was copied." -ForegroundColor Yellow
    Write-Host "The export is still in $exportDir. Check folder redirection in Windows App, then reconnect." -ForegroundColor Yellow
}