<#
.SYNOPSIS
    Proves the lab VM records every event ID the 15 detections rely on.

.DESCRIPTION
    Performs a set of harmless, clearly labelled actions, undoes all of them, then counts the
    events each one produced. Everything it creates is named "WTDL-Test" so it is easy to
    recognise later as test activity rather than an attack.

    Actions (all reversed before the script ends):
      - runs whoami.exe ................................... Sysmon 1, Security 4688
      - writes then deletes C:\lab\wtdl-test.dmp .......... Sysmon 11
      - creates then deletes HKCU\Software\WTDL-Test\CurrentVersion\Run
        (not a real autorun location: nothing runs at logon) ... Sysmon 12, 13
      - creates a local user (no password) and a local group, adds the user
        to the group, then deletes both ................... Security 4720, 4732
      - registers then removes a scheduled task with no trigger
        (it never runs) ................................... Security 4698, Task Scheduler 106
      - creates then deletes a service that is never started ... System 7045, Security 4697
      - lowers Defender's scan CPU limit by 5 percent, then restores it
        (protection is unchanged) ......................... Defender 5007
    Checked from Windows' own activity in the last 24 hours (nothing generated):
      - LSASS handle access by Windows itself ............. Sysmon 10
      - admin logons and RDP logons ....................... Security 4672, 4624 (logon type 10)
    Running this script also produces PowerShell 4104 events.

    Results are printed and saved to C:\lab\telemetry-check-<date>.csv.

.NOTES
    Run in an elevated Windows PowerShell 5.1 window opened after Enable-LabLogging.ps1 has run.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

function Get-EventCount {
    param(
        [Parameter(Mandatory)] [string]   $LogName,
        [Parameter(Mandatory)] [int]      $Id,
        [Parameter(Mandatory)] [datetime] $Since
    )
    try {
        @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id; StartTime = $Since } -ErrorAction Stop).Count
    }
    catch {
        0   # Get-WinEvent throws when nothing matches
    }
}

function Get-RdpLogonCount {
    # 4624 with LogonType 10 (RemoteInteractive) in the last 24 hours (86400000 ms).
    $xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 86400000]]] and *[EventData[Data[@Name='LogonType']='10']]"
    try {
        @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath -ErrorAction Stop).Count
    }
    catch {
        0
    }
}

$start       = (Get-Date).AddSeconds(-5)
$dayAgo      = (Get-Date).AddHours(-24)
$dmpFile     = 'C:\lab\wtdl-test.dmp'
$regKey      = 'HKCU:\Software\WTDL-Test'
$userName    = 'WTDL-TestUser'
$groupName   = 'WTDL-TestGroup'
$taskName    = 'WTDL-TestTask'
$serviceName = 'WTDL-TestService'
$originalCpuLoad = $null

Write-Host 'Generating test activity...' -ForegroundColor Cyan
try {
    # Process creation
    & "$env:WINDIR\System32\whoami.exe" | Out-Null

    # File creation (.dmp matches the Sysmon FileCreate filter)
    Set-Content -Path $dmpFile -Value 'WTDL telemetry test file'

    # Registry key and value under a path that contains \CurrentVersion\Run
    New-Item -Path "$regKey\CurrentVersion\Run" -Force | Out-Null
    New-ItemProperty -Path "$regKey\CurrentVersion\Run" -Name 'WTDL-TestValue' -PropertyType String -Value 'WTDL telemetry test' -Force | Out-Null

    # Local user and local group
    New-LocalUser -Name $userName -NoPassword -Description 'WTDL telemetry test account' | Out-Null
    New-LocalGroup -Name $groupName -Description 'WTDL telemetry test group' | Out-Null
    Add-LocalGroupMember -Group $groupName -Member $userName

    # Scheduled task with no trigger: registered, but it never runs
    $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\cmd.exe" -Argument '/c exit 0'
    Register-ScheduledTask -TaskName $taskName -Action $action -Description 'WTDL telemetry test task' | Out-Null

    # Service that is created but never started
    New-Service -Name $serviceName -BinaryPathName "$env:WINDIR\System32\cmd.exe /c exit 0" -StartupType Manual -Description 'WTDL telemetry test service' | Out-Null

    # Defender configuration change that does not reduce protection
    $originalCpuLoad = (Get-MpPreference).ScanAvgCPULoadFactor
    Set-MpPreference -ScanAvgCPULoadFactor ([Math]::Max(5, $originalCpuLoad - 5))
}
finally {
    Write-Host 'Cleaning up...' -ForegroundColor Cyan
    if ($null -ne $originalCpuLoad) { Set-MpPreference -ScanAvgCPULoadFactor $originalCpuLoad }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { sc.exe delete $serviceName | Out-Null }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    if (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name $groupName }
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $userName }
    if (Test-Path -Path $regKey) { Remove-Item -Path $regKey -Recurse -Force }
    if (Test-Path -Path $dmpFile) { Remove-Item -Path $dmpFile -Force }
}

Write-Host 'Waiting for events to be written...' -ForegroundColor Cyan
Start-Sleep -Seconds 5

$sysmon = 'Microsoft-Windows-Sysmon/Operational'
$checks = @(
    @{ Log = $sysmon; Id = 1;  Shows = 'Process creation';                 UsedBy = 'WTD-001 to 006, 010, 011'; Since = $start },
    @{ Log = $sysmon; Id = 10; Shows = 'LSASS access by Windows (24h)';    UsedBy = 'WTD-009';                  Since = $dayAgo },
    @{ Log = $sysmon; Id = 11; Shows = 'File created';                     UsedBy = 'WTD-008, 010';             Since = $start },
    @{ Log = $sysmon; Id = 12; Shows = 'Registry key created or deleted';  UsedBy = 'WTD-007, 014';             Since = $start },
    @{ Log = $sysmon; Id = 13; Shows = 'Registry value set';               UsedBy = 'WTD-007, 014';             Since = $start },
    @{ Log = 'Security'; Id = 4688; Shows = 'Process creation';            UsedBy = 'WTD-001 to 004';           Since = $start },
    @{ Log = 'Security'; Id = 4720; Shows = 'User account created';        UsedBy = 'WTD-012';                  Since = $start },
    @{ Log = 'Security'; Id = 4732; Shows = 'Member added to local group'; UsedBy = 'WTD-012, 013';             Since = $start },
    @{ Log = 'Security'; Id = 4698; Shows = 'Scheduled task created';      UsedBy = 'WTD-005';                  Since = $start },
    @{ Log = 'Security'; Id = 4697; Shows = 'Service installed';           UsedBy = 'WTD-006';                  Since = $start },
    @{ Log = 'Security'; Id = 4672; Shows = 'Admin logon (24h)';           UsedBy = 'WTD-015';                  Since = $dayAgo },
    @{ Log = 'System';   Id = 7045; Shows = 'Service installed';           UsedBy = 'WTD-006';                  Since = $start },
    @{ Log = 'Microsoft-Windows-TaskScheduler/Operational';    Id = 106;  Shows = 'Scheduled task registered'; UsedBy = 'WTD-005';      Since = $start },
    @{ Log = 'Microsoft-Windows-PowerShell/Operational';       Id = 4104; Shows = 'PowerShell script block';   UsedBy = 'WTD-001, 002'; Since = $start },
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; Shows = 'Defender setting changed';  UsedBy = 'WTD-014';      Since = $start }
)

$results = @()
foreach ($check in $checks) {
    $count  = Get-EventCount -LogName $check.Log -Id $check.Id -Since $check.Since
    $result = 'MISSING'
    if ($count -gt 0) { $result = 'OK' }
    $results += [pscustomobject]@{
        Log    = ($check.Log -replace '^Microsoft-Windows-', '')
        Id     = $check.Id
        Shows  = $check.Shows
        UsedBy = $check.UsedBy
        Count  = $count
        Result = $result
    }
}

$rdpCount  = Get-RdpLogonCount
$rdpResult = 'MISSING'
if ($rdpCount -gt 0) { $rdpResult = 'OK' }
$results += [pscustomobject]@{
    Log    = 'Security'
    Id     = 4624
    Shows  = 'RDP logon, type 10 (24h)'
    UsedBy = 'WTD-015'
    Count  = $rdpCount
    Result = $rdpResult
}

$results | Format-Table -AutoSize -Property Log, Id, Shows, UsedBy, Count, Result

$csvPath = 'C:\lab\telemetry-check-{0}.csv' -f (Get-Date -Format 'yyyy-MM-dd')
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Saved results to $csvPath"

$missing = @($results | Where-Object { $_.Result -eq 'MISSING' })
if ($missing.Count -eq 0) {
    Write-Host 'All required event IDs are being recorded.' -ForegroundColor Green
}
else {
    Write-Host "$($missing.Count) event ID(s) missing: paste this table to Claude." -ForegroundColor Yellow
}