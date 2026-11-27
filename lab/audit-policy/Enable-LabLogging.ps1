<#
.SYNOPSIS
    Turns on the Windows logging that the Windows Threat Detection Library's detections rely on.

.DESCRIPTION
    Run on the lab VM in an elevated PowerShell window. Safe to re-run: every setting is
    applied the same way each time. Sysmon is configured separately (lab/sysmon/).

    What it enables, and which detections use it:
      Advanced audit policy
        Process Creation (4688) ...................... WTD-001 to WTD-004 (backup to Sysmon 1)
        Logon, Special Logon (4624, 4625, 4672) ....... WTD-015
        User Account Management (4720) ................ WTD-012
        Security Group Management (4732) .............. WTD-012, WTD-013
        Other Object Access Events (4698) ............. WTD-005
        Security System Extension (4697) .............. WTD-006
      Full command lines in 4688 events
      PowerShell script block logging (4104) .......... WTD-001, WTD-002
      Task Scheduler Operational log (106) ............ WTD-005 (second source)
      Larger event logs, so test events survive until they are exported

.NOTES
    Script block logging applies to PowerShell windows opened AFTER this script runs.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

function Set-RegistryDword {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [int]    $Value
    )
    # Create the key only if it is missing: New-Item -Force on an existing key would wipe its values.
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

# 1. Make the per-subcategory ("advanced") audit settings take priority over the older category settings.
Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1

# 2. Advanced audit policy.
$auditSettings = @(
    @{ Subcategory = 'Process Creation';           Success = 'enable'; Failure = 'disable' },
    @{ Subcategory = 'Logon';                      Success = 'enable'; Failure = 'enable'  },
    @{ Subcategory = 'Special Logon';              Success = 'enable'; Failure = 'disable' },
    @{ Subcategory = 'User Account Management';    Success = 'enable'; Failure = 'enable'  },
    @{ Subcategory = 'Security Group Management';  Success = 'enable'; Failure = 'enable'  },
    @{ Subcategory = 'Other Object Access Events'; Success = 'enable'; Failure = 'enable'  },
    @{ Subcategory = 'Security System Extension';  Success = 'enable'; Failure = 'enable'  }
)
foreach ($setting in $auditSettings) {
    auditpol.exe /set /subcategory:"$($setting.Subcategory)" /success:$($setting.Success) /failure:$($setting.Failure) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for '$($setting.Subcategory)'" }
}

# 3. Record the full command line in 4688 process creation events.
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Set-RegistryDword -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1

# 4. PowerShell script block logging: Windows PowerShell 5.1 writes event 4104 to
#    Microsoft-Windows-PowerShell/Operational.
$scriptBlockKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
Set-RegistryDword -Path $scriptBlockKey -Name 'EnableScriptBlockLogging' -Value 1

# 5. Turn on the Task Scheduler operational log (off by default).
wevtutil.exe set-log 'Microsoft-Windows-TaskScheduler/Operational' /enabled:true
if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed to enable the Task Scheduler log' }

# 6. Bigger logs (sizes in bytes), so test events are still there when they are exported.
$logSizes = [ordered]@{
    'Security'                                       = 268435456  # 256 MB
    'Microsoft-Windows-Sysmon/Operational'           = 268435456  # 256 MB
    'Microsoft-Windows-PowerShell/Operational'       = 134217728  # 128 MB
    'System'                                         = 67108864   # 64 MB
    'Microsoft-Windows-Windows Defender/Operational' = 67108864   # 64 MB
    'Microsoft-Windows-TaskScheduler/Operational'    = 33554432   # 32 MB
}
foreach ($log in $logSizes.Keys) {
    wevtutil.exe set-log "$log" /maxsize:$($logSizes[$log])
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed to resize '$log'" }
}

# 7. Show what is now in place.
Write-Host ''
Write-Host '== Audit policy ==' -ForegroundColor Cyan
foreach ($setting in $auditSettings) {
    $pattern = '^\s+' + [regex]::Escape($setting.Subcategory) + '\s{2,}'
    auditpol.exe /get /subcategory:"$($setting.Subcategory)" | Select-String -Pattern $pattern
}

Write-Host ''
Write-Host '== Registry settings ==' -ForegroundColor Cyan
Get-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' |
    Select-Object -Property ProcessCreationIncludeCmdLine_Enabled
Get-ItemProperty -Path $scriptBlockKey -Name 'EnableScriptBlockLogging' |
    Select-Object -Property EnableScriptBlockLogging

Write-Host ''
Write-Host '== Event logs ==' -ForegroundColor Cyan
Get-WinEvent -ListLog @($logSizes.Keys) |
    Format-Table -AutoSize -Property LogName, IsEnabled, @{ Name = 'MaxSizeMB'; Expression = { $_.MaximumSizeInBytes / 1MB } }

Write-Host 'Done. Open a NEW PowerShell window before testing script block logging.' -ForegroundColor Green