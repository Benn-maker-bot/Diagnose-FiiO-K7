#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses, and optionally fixes, a FiiO K7 USB DAC that Windows 11 fails to
    recognise when the K7 is switched on.

.DESCRIPTION
    The script answers one question: when the K7 fails, does Windows see it at all?

      A. Windows never sees a USB attach        -> K7 / cable / port side (hardware path)
      B. Windows sees an "Unknown USB Device"   -> USB enumeration failure (link level:
         (Device Descriptor Request Failed)        K7 start-up timing, cable, port, hub, power)
      C. Windows sees the K7 but it fails to    -> Windows side (driver / known issue)
         start (Code 10, 28, 39, 52 ...)
      D. The K7 starts but no audio output      -> Windows audio stack / audio software
         device appears

    It checks:
      * Windows build, Insider channel, and the open Microsoft known issue that stops
        some USB Audio Class 1.0 devices starting (Code 10) after the 8 September 2026
        update (KB5124008) and later builds.
      * Every K7 device instance (present and phantom), its driver, problem code,
        last arrival/removal time and the USB path back to the controller.
      * "Unknown USB Device" (VID_0000) entries that betray failed enumerations.
      * USB selective suspend, PCIe link state power management, Fast Startup and
        per-device "allow the computer to turn off this device" settings.
      * Kernel-PnP and System event logs for K7 start failures and failed enumerations.
      * FiiO driver packages, audio services, audio endpoints and audio software that
        can interfere (Sonic Studio, Nahimic, Voicemeeter, Equalizer APO and so on).

    Modes:
      (default)     Read-only report.
      -Watch        Live capture: you switch the K7 on and the script records exactly
                    what Windows sees, then gives a verdict for that attempt.
      -Fix          Applies fixes after asking about each one. Saves a backup first.
      -RestoreFrom  Reverts the changes recorded in a backup file.

    A full transcript goes to a "reports" folder next to the script (or -OutputFolder).

.EXAMPLE
    .\Diagnose-FiiOK7.ps1
    Read-only report.

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -Watch
    Leave the K7 off for as long as it normally sits off, then run this and switch it on
    when prompted. Run it again on a day it fails if the first attempt succeeds.

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -Fix
    Report, then offer each fix in turn (relaunches elevated if needed).

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -RestoreFrom ".\reports\FiiO-K7-Backup-20261031-0800.json"

.NOTES
    Run from an elevated PowerShell for the complete picture (event logs and device
    power settings need administrator rights). If Windows blocks the script:
        Unblock-File .\Diagnose-FiiOK7.ps1
        powershell -ExecutionPolicy Bypass -File .\Diagnose-FiiOK7.ps1
#>
[CmdletBinding()]
param(
    # Live capture mode: record what Windows sees while the K7 is switched on
    [switch]$Watch,
    # Length of the live capture, in seconds
    [ValidateRange(15, 600)]
    [int]$WatchSeconds = 60,
    # Offer to apply fixes (each one is confirmed individually and backed up first)
    [switch]$Fix,
    # Skip the Y/N prompts and apply every fix (only meaningful with -Fix)
    [switch]$Force,
    # How many days of event log history to search
    [ValidateRange(1, 90)]
    [int]$Days = 14,
    # Path to a backup JSON created by -Fix; reverts the changes it recorded
    [string]$RestoreFrom,
    # Where reports and backups are written (defaults to a "reports" folder beside the script)
    [string]$OutputFolder = (Join-Path $PSScriptRoot 'reports')
)

# Strict mode turns use of unset variables into errors, which catches typos early.
# 'Continue' keeps the script running when a single query fails: a diagnostic tool
# should report as much as it can rather than stop at the first problem.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# FiiO's USB vendor ID is 0x2972. XMOS (the K7's USB receiver chip) is 0x20B1;
# a K7 in firmware-update (DFU) mode or with generic firmware can show that ID.
$K7IdPattern      = 'VID_(2972|20B1)'                              # matches any instance ID or event text naming the K7's vendor
$K7NamePattern    = 'FiiO'                                         # fallback: match on the friendly name
$K7RootPattern    = '^USB\\VID_(2972|20B1)&PID_[0-9A-F]{4}\\'      # the top-level USB device node (not its audio child nodes)
# Strings that indicate a failed enumeration (the device attached but never described itself)
$UnknownPattern   ='VID_0000|Unknown USB Device|Device Descriptor Request Failed|Port Reset Failed|Set Address Failed'
# Third-party audio utilities that insert themselves into the Windows audio stack
# and have been known to interfere with USB audio devices
$AudioSwPattern   ='SonicStudio|Sonic Studio|ArmouryCrate|Armoury Crate|Nahimic|Voicemeeter|VB-Audio|SteelSeries|Sonar|FxSound|EqualizerAPO|Equalizer APO|Peace Equalizer|\bDTS\b|Dolby|Boom3D|Realtek Audio Console|RtkAudUService|Waves MaxxAudio|MaxxAudio|SoundSwitch|Wave Link|NVIDIA Broadcast|Krisp'

# Power-setting GUIDs used with powercfg.exe (a "sub" is the setting group, the other is the setting)
$GUID_SUB_USB     ='2a737441-1930-4402-8d77-b2bebba308a3'
$GUID_USB_SS      = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'   # USB selective suspend
$GUID_SUB_PCIE    = '501a4d13-42af-4429-9fd1-a8218c268e20'
$GUID_PCIE_LSPM   = 'ee12f906-d277-404b-b6da-e5fa1a576df5'   # PCIe Link State Power Management

# Updates tied to the current Microsoft USB Audio Class 1.0 known issue
$KnownIssueKBs = @{
    'KB5124008' = 'September 8, 2026 security update - introduced the USB Audio Class 1.0 Code 10 issue (24H2/25H2)'
    'KB5124012' = 'September 2026 update for 26H1 - same USB Audio Class 1.0 issue'
    'KB5129195' = 'September 14, 2026 out-of-band update - partial fix (multichannel only; Code 10 still open)'
    'KB5127648' = 'October 2026 update - USB audio Code 10 still listed as an open (mitigated) issue'
}

# Device Manager problem codes (ConfigManagerErrorCode) translated to plain English
$ProblemText = @{
    0  = 'Working'
    1  = 'Not configured correctly'
    3  = 'Driver may be corrupted / out of memory'
    10 = 'Device cannot start'
    12 = 'Not enough free resources'
    14 = 'Needs a restart'
    18 = 'Drivers need reinstalling'
    19 = 'Registry configuration damaged'
    21 = 'Windows is removing the device'
    22 = 'Device is disabled'
    24 = 'Not present, not working properly, or drivers missing'
    28 = 'Drivers not installed'
    31 = 'Not working properly - Windows cannot load the drivers'
    37 = 'Driver failed to initialise'
    38 = 'Previous driver instance still in memory'
    39 = 'Driver corrupted or missing'
    41 = 'Driver loaded but cannot find the hardware'
    43 = 'Windows stopped the device - it reported problems (typical of a failed USB descriptor request)'
    45 = 'Not currently connected (phantom)'
    47 = 'Prepared for safe removal'
    48 = 'Driver blocked from starting'
    52 = 'Driver signature cannot be verified'
}

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
# Fixing or restoring changes system settings, so it needs administrator rights.
# If we are not elevated, relaunch this same script (with the same parameters) in an
# elevated window and end this instance. A plain read-only report runs un-elevated,
# though with less detail (event logs and device power flags need admin).
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (($Fix -or $RestoreFrom) -and -not $IsAdmin) {
    Write-Host 'Fixes and restores need administrator rights. Relaunching elevated...' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $argList += ('-{0}' -f $kv.Key) }
        }
        else {
            $argList += ('-{0}' -f $kv.Key)
            $argList += ('"{0}"' -f $kv.Value)
        }
    }
    $exe = (Get-Process -Id $PID).Path
    try { Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs | Out-Null }
    catch { Write-Host "Elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red }
    return
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
# Every run gets a timestamped report (and, with -Fix, a matching backup file).
# If the output folder cannot be created, fall back to the temp folder.
$Stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    try { New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction Stop | Out-Null }
    catch { $OutputFolder = $env:TEMP }
}
$ReportPath = Join-Path $OutputFolder "FiiO-K7-Report-$Stamp.txt"
$BackupPath = Join-Path $OutputFolder "FiiO-K7-Backup-$Stamp.json"
# Every finding is collected here so the end of the run can summarise them and
# decide whether to suggest -Fix.
$Findings   = New-Object System.Collections.Generic.List[object]

# Prints a cyan banner that starts a numbered section of the report
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

# Records and prints one finding. Level: OK (good), Info (neutral), Warn (worth
# looking at) or Fault (a definite problem). Advice is the suggested next step.
function Write-Finding {
    param(
        [ValidateSet('OK', 'Info', 'Warn', 'Fault')][string]$Level,
        [string]$Area,
        [string]$Message,
        [string]$Advice
    )
    $colour = @{ OK = 'Green'; Info = 'Gray'; Warn = 'Yellow'; Fault = 'Red' }[$Level]
    Write-Host ('  [{0,-5}] {1}' -f $Level.ToUpper(), $Message) -ForegroundColor $colour
    if ($Advice) { Write-Host "          -> $Advice" -ForegroundColor DarkGray }
    $Findings.Add([pscustomobject]@{ Level = $Level; Area = $Area; Message = $Message; Advice = $Advice })
}

function Write-Detail {
    param([string]$Text)
    Write-Host "          $Text" -ForegroundColor DarkGray
}

# Asks a Y/N question; -Force answers yes automatically
function Confirm-Step {
    param([string]$Question)
    if ($Force) { return $true }
    $answer = Read-Host "  $Question [Y/N]"
    return ($answer -match '^(y|yes)$')
}

function Get-ProblemText {
    param([int]$Code)
    if ($ProblemText.ContainsKey($Code)) { return $ProblemText[$Code] }
    return "Problem code $Code"
}

# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------
# Device properties fetched for each K7 / Unknown USB device instance
$DevKeys = @(
    'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_Service', 'DEVPKEY_Device_DriverVersion',
    'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverDate',
    'DEVPKEY_Device_Parent', 'DEVPKEY_Device_LocationPaths', 'DEVPKEY_Device_BusReportedDeviceDesc',
    'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate', 'DEVPKEY_Device_IsPresent',
    'DEVPKEY_Device_ContainerId'
)

# Returns a hashtable of the DEVPKEY_* properties above for one device instance.
# Properties a device does not have are simply absent.
function Get-DevProps {
    param([string]$InstanceId)
    $h = @{}
    try {
        $props = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $DevKeys -ErrorAction SilentlyContinue
        foreach ($p in @($props)) { if ($p -and $null -ne $p.Data) { $h[$p.KeyName] = $p.Data } }
    }
    catch { }
    return $h
}

# Safe hashtable lookup: returns $null instead of erroring under strict mode
function Get-PropValue {
    param([hashtable]$Props, [string]$Key)
    if ($Props.ContainsKey($Key)) { return $Props[$Key] }
    return $null
}

# Walks up the device tree from the K7 (device -> hub -> root hub -> controller ...)
# and returns each parent. Used to spot external hubs between the K7 and the PC.
# Capped at 12 levels as a guard against loops.
function Get-ParentChain {
    param([string]$InstanceId)
    $chain = New-Object System.Collections.Generic.List[object]
    $current = $InstanceId
    for ($i = 0; $i -lt 12; $i++) {
        $parent = $null
        $pp = Get-PnpDeviceProperty -InstanceId $current -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
        if ($pp) { $parent = $pp.Data }
        if (-not $parent -or $parent -like 'HTREE\ROOT*' -or $parent -like 'ACPI_HAL*') { break }
        $dev = Get-PnpDevice -InstanceId $parent -ErrorAction SilentlyContinue
        $name = $null; $class = $null
        if ($dev) { $name = $dev.FriendlyName; $class = $dev.Class }
        $chain.Add([pscustomobject]@{ InstanceId = $parent; Name = $name; Class = $class })
        $current = $parent
    }
    return $chain
}

function Get-RegDword {
    param([string]$Path, [string]$Name)
    # Reads without throwing, so missing keys/values do not clutter the transcript
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $key) { return $null }
    $v = $key.GetValue($Name, $null)
    if ($null -eq $v) { return $null }
    return [int]$v
}

function Get-EventText {
    # Message text can be empty when provider metadata fails to load; the XML always
    # carries the device instance ID, so match against both.
    param($Rec)
    $msg = ''
    try { $msg = [string]$Rec.Message } catch { }
    $xml = ''
    try { $xml = $Rec.ToXml() } catch { }
    return "$msg $xml"
}

# Reads one power-plan setting's current AC (mains) and DC (battery) value by
# parsing the text output of "powercfg /query". Values are null if unreadable.
function Get-PowerSetting {
    param([string]$Sub, [string]$Setting)
    $out = & powercfg.exe /query SCHEME_CURRENT $Sub $Setting 2>$null
    $result = [pscustomobject]@{ AC = $null; DC = $null }
    if (-not $out) { return $result }
    $text = $out -join "`n"
    $ac = [regex]::Match($text, 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)')
    $dc = [regex]::Match($text, 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)')
    if ($ac.Success) { $result.AC = [Convert]::ToInt32($ac.Groups[1].Value, 16) }
    if ($dc.Success) { $result.DC = [Convert]::ToInt32($dc.Groups[1].Value, 16) }
    return $result
}

# Name of the active power plan, e.g. "Balanced"
function Get-ActiveSchemeName {
    $line = & powercfg.exe /getactivescheme 2>$null
    $m = [regex]::Match(($line -join ' '), '\(([^)]+)\)\s*$')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

# GUID of the active power plan (needed so backups restore to the right plan)
function Get-ActiveSchemeGuid {
    $line = & powercfg.exe /getactivescheme 2>$null
    $m = [regex]::Match(($line -join ' '), '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    if ($m.Success) { return $m.Value }
    return $null
}

# Returns the WMI records behind Device Manager's "Allow the computer to turn off
# this device to save power" checkbox. Empty if not elevated.
function Get-MSPowerEntries {
    try { return @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop) }
    catch { return @() }
}

# Finds the power record for a device (record names start with the instance ID)
function Find-MSPowerEntry {
    param([object[]]$Entries, [string]$InstanceId)
    foreach ($e in $Entries) {
        if ($e.InstanceName -and $e.InstanceName.StartsWith($InstanceId, [StringComparison]::OrdinalIgnoreCase)) { return $e }
    }
    return $null
}

# Collapses whitespace and truncates long event messages so they fit on one line
function Get-ShortMessage {
    param([string]$Message, [int]$Max = 220)
    if (-not $Message) { return '' }
    $flat = ($Message -replace '\s+', ' ').Trim()
    if ($flat.Length -gt $Max) { return $flat.Substring(0, $Max) + '...' }
    return $flat
}

# ---------------------------------------------------------------------------
# Restore mode
# ---------------------------------------------------------------------------
# Reads a backup JSON written by -Fix and puts back the original values:
# power-plan settings, registry values (deleting any that did not exist before)
# and the per-device "allow turn off" flags. Then exits without running diagnostics.
if ($RestoreFrom) {
    Start-Transcript -LiteralPath $ReportPath -Force | Out-Null
    Write-Section 'Restoring settings from backup'
    if (-not (Test-Path -LiteralPath $RestoreFrom)) {
        Write-Host "  Backup file not found: $RestoreFrom" -ForegroundColor Red
        Stop-Transcript | Out-Null
        return
    }
    $b = Get-Content -LiteralPath $RestoreFrom -Raw | ConvertFrom-Json
    $scheme = 'SCHEME_CURRENT'
    if ($b.SchemeGuid) { $scheme = $b.SchemeGuid }
    foreach ($p in @($b.Power)) {
        if ($null -ne $p.AC) { & powercfg.exe /setacvalueindex $scheme $p.Sub $p.Setting $p.AC | Out-Null }
        if ($null -ne $p.DC) { & powercfg.exe /setdcvalueindex $scheme $p.Sub $p.Setting $p.DC | Out-Null }
        Write-Host "  Restored power setting $($p.Name): AC=$($p.AC) DC=$($p.DC)"
    }
    & powercfg.exe /setactive $scheme | Out-Null
    foreach ($r in @($b.Registry)) {
        try {
            if ($r.Existed) {
                New-ItemProperty -LiteralPath $r.Path -Name $r.Name -Value ([int]$r.Value) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Write-Host "  Restored $($r.Path)\$($r.Name) = $($r.Value)"
            }
            else {
                Remove-ItemProperty -LiteralPath $r.Path -Name $r.Name -ErrorAction Stop
                Write-Host "  Removed $($r.Path)\$($r.Name) (it did not exist before)"
            }
        }
        catch { Write-Host "  Could not restore $($r.Path)\$($r.Name): $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    $entries = @(Get-MSPowerEntries)
    foreach ($m in @($b.MSPower)) {
        $o = $entries | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        if ($o) {
            try {
                Set-CimInstance -InputObject $o -Property @{ Enable = [bool]$m.Enable } -ErrorAction Stop
                Write-Host "  Restored 'allow turn off' = $($m.Enable) for $($m.InstanceName)"
            }
            catch { Write-Host "  Could not restore power management for $($m.InstanceName)" -ForegroundColor Yellow }
        }
    }
    Write-Host ''
    Write-Host '  Restore complete. Restart Windows for every change to take effect.' -ForegroundColor Green
    Stop-Transcript | Out-Null
    return
}

# ---------------------------------------------------------------------------
# Start report
# ---------------------------------------------------------------------------
Start-Transcript -LiteralPath $ReportPath -Force | Out-Null
Write-Host "FiiO K7 USB recognition diagnostics - $(Get-Date -Format 'dddd d MMMM yyyy HH:mm:ss')" -ForegroundColor White
Write-Host "Report: $ReportPath"
if (-not $IsAdmin) {
    Write-Host 'Not running as administrator: some event logs and device power settings will be missing.' -ForegroundColor Yellow
    Write-Host 'Re-run from an elevated PowerShell for the full picture.' -ForegroundColor Yellow
}

# Cache device lists once: enumerating devices is slow, so every section below
# reuses these. $AllDevices includes phantom (disconnected) devices; $PresentIds
# is the set of instance IDs that are connected right now.
Write-Host ''
Write-Host 'Enumerating devices (this can take a few seconds)...' -ForegroundColor DarkGray
$AllDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue)
$PresentIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($d in @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue)) { [void]$PresentIds.Add($d.InstanceId) }

# ---------------------------------------------------------------------------
# 1. System
# ---------------------------------------------------------------------------
# Establish the Windows build, any Insider channel, motherboard/BIOS and recent
# updates, so the report can be matched against Microsoft's known USB audio issue.
Write-Section '1. Windows and hardware'
$cv      = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$Build   = [int]$cv.CurrentBuildNumber
$Ubr     = $cv.UBR
$Display = $cv.DisplayVersion
$branch  = $null
$selfHost = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability' -ErrorAction SilentlyContinue
if ($selfHost -and ($selfHost.PSObject.Properties.Name -contains 'BranchName')) { $branch = $selfHost.BranchName }
$board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
$bios  = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

$osName = [string]$cv.ProductName
if ($Build -ge 22000) { $osName = $osName -replace 'Windows 10', 'Windows 11' }   # the registry still says "Windows 10" on Windows 11
Write-Detail "Windows: $osName $Display, build $Build.$Ubr"
if ($branch) { Write-Detail "Insider branch: $branch" }
if ($board)  { Write-Detail "Motherboard: $($board.Manufacturer) $($board.Product)" }
if ($bios)   { Write-Detail "BIOS: $($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate))" }

if ($branch) {
    Write-Finding Info 'Windows' "This PC runs a Windows Insider build ($branch)." `
        'Insider builds carry the USB audio regressions first and get fixes later; keep that in mind when reading the verdict.'
}

# Known issue: some USB Audio Class 1.0 devices fail with Code 10 (24H2 = 26100, 25H2 = 26200, 26H1/26H2 = 26xxx/28xxx)
$AffectedBuild = ($Build -ge 26100)
$hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending)
$foundKBs = @()
foreach ($kb in $KnownIssueKBs.Keys) {
    if ($hotfixes | Where-Object { $_.HotFixID -eq $kb }) { $foundKBs += $kb }
}
if ($foundKBs.Count -gt 0) {
    foreach ($kb in $foundKBs) { Write-Detail "Installed: $kb - $($KnownIssueKBs[$kb])" }
}
Write-Detail ('Latest updates: ' + (($hotfixes | Select-Object -First 5 | ForEach-Object { "$($_.HotFixID) ($(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '?' }))" }) -join ', '))

# ---------------------------------------------------------------------------
# 2. K7 devices
# ---------------------------------------------------------------------------
# Find every device node belonging to the K7 (present or phantom), show its driver
# and health, and work out which USB Audio Class driver it is running on:
#   UAC1 = usbaudio.sys (Microsoft, affected by the known issue)
#   UAC2 = usbaudio2.sys (Microsoft)
#   Vendor = FiiO's own Thesycon-based driver
Write-Section '2. FiiO K7 device instances'
$K7All = @($AllDevices | Where-Object { $_.InstanceId -match $K7IdPattern -or ($_.FriendlyName -and $_.FriendlyName -match $K7NamePattern) })
$K7Roots = @($K7All | Where-Object { $_.InstanceId -match $K7RootPattern })
$K7RootsPresent = @($K7Roots | Where-Object { $PresentIds.Contains($_.InstanceId) })
$K7Phantoms = @($K7All | Where-Object { -not $PresentIds.Contains($_.InstanceId) })

$K7Mode = $null          # 'UAC1', 'UAC2', 'Vendor'
$K7PresentOK = $false
$K7PresentError = $null
$K7ChainForFix = @()

if ($K7All.Count -eq 0) {
    Write-Finding Warn 'Device' 'Windows has no record of any FiiO/XMOS USB device on this PC.' `
        'Switch the K7 on, set INPUT to USB, wait until Windows recognises it, then run this script again.'
}
else {
    foreach ($d in ($K7All | Sort-Object InstanceId)) {
        $present = $PresentIds.Contains($d.InstanceId)
        $props   = Get-DevProps $d.InstanceId
        $code    = Get-PropValue $props 'DEVPKEY_Device_ProblemCode'
        $svc     = Get-PropValue $props 'DEVPKEY_Device_Service'
        $ver     = Get-PropValue $props 'DEVPKEY_Device_DriverVersion'
        $prov    = Get-PropValue $props 'DEVPKEY_Device_DriverProvider'
        $inf     = Get-PropValue $props 'DEVPKEY_Device_DriverInfPath'
        $bus     = Get-PropValue $props 'DEVPKEY_Device_BusReportedDeviceDesc'
        $arr     = Get-PropValue $props 'DEVPKEY_Device_LastArrivalDate'
        $rem     = Get-PropValue $props 'DEVPKEY_Device_LastRemovalDate'
        $state   = if ($present) { 'PRESENT' } else { 'not connected' }

        Write-Host ''
        Write-Host ("  {0}  [{1}]" -f $d.FriendlyName, $state) -ForegroundColor White
        Write-Detail "Instance : $($d.InstanceId)"
        Write-Detail "Class    : $($d.Class)   Status: $($d.Status)"
        if ($bus)  { Write-Detail "USB name : $bus" }
        if ($svc)  { Write-Detail "Driver   : service '$svc', $prov $ver ($inf)" }
        if ($arr)  { Write-Detail "Arrived  : $arr" }
        if ($rem)  { Write-Detail "Removed  : $rem" }

        if ($present -and $d.Class -eq 'MEDIA') {
            switch -Regex ($svc) {
                '^usbaudio$'  { $K7Mode = 'UAC1' }
                '^usbaudio2$' { $K7Mode = 'UAC2' }
                default       { if ($svc) { $K7Mode = 'Vendor' } }
            }
        }

        if ($present) {
            $c = 0
            if ($null -ne $code) { $c = [int]$code } elseif ($d.ConfigManagerErrorCode) { $c = [int]$d.ConfigManagerErrorCode }
            if ($c -ne 0) {
                $K7PresentError = $c
                Write-Finding Fault 'Device' "$($d.FriendlyName) is present but has Code $c - $(Get-ProblemText $c)." `
                    'Windows can see the K7 but cannot start it: this is a Windows/driver-side failure.'
            }
            elseif ($d.InstanceId -match $K7RootPattern) {
                $K7PresentOK = $true
            }
        }
    }

    Write-Host ''
    if ($K7RootsPresent.Count -gt 0) {
        if ($K7PresentOK -and -not $K7PresentError) {
            Write-Finding OK 'Device' 'The K7 is connected and Windows reports it as working right now.'
        }
    }
    else {
        Write-Finding Info 'Device' 'The K7 is not connected right now (or is switched off / on a different input).'
    }

    $rootCount = @($K7Roots).Count
    if ($rootCount -gt 1) {
        Write-Finding Info 'Device' "Windows holds $rootCount separate K7 USB instances (one per port/serial it has been seen on)." `
            'Harmless in itself, but stale instances are worth clearing; -Fix removes the disconnected ones.'
    }

    switch ($K7Mode) {
        'UAC1'   { Write-Finding Warn 'Driver' 'The K7 is running on the in-box USB Audio Class 1.0 driver (usbaudio.sys).' `
                       'Microsoft has an open known issue where some UAC 1.0 devices fail with Code 10 on current builds.' }
        'UAC2'   { Write-Finding Info 'Driver' 'The K7 is running on the in-box USB Audio Class 2.0 driver (usbaudio2.sys).' }
        'Vendor' { Write-Finding Info 'Driver' 'The K7 is running on a vendor driver (FiiO/Thesycon).' }
    }
}

# Known-issue verdict
if ($AffectedBuild -and $K7Mode -eq 'UAC1') {
    Write-Finding Warn 'Windows' "Build $Build is in the range covered by Microsoft's open USB Audio Class 1.0 Code 10 issue, and the K7 uses that class." `
        'If you see Code 10 on the K7, this known issue is the likely cause. Installing the FiiO USB DAC driver moves the K7 off usbaudio.sys.'
}
elseif ($AffectedBuild -and $K7Mode) {
    Write-Finding OK 'Windows' "Microsoft's open USB audio Code 10 issue only affects USB Audio Class 1.0; the K7 is not using that driver."
}

# ---------------------------------------------------------------------------
# 3. Failed enumerations
# ---------------------------------------------------------------------------
# When a USB device attaches but fails to describe itself, Windows keeps an
# "Unknown USB Device" entry (VID_0000). Finding these means the problem is at
# the USB link level rather than a driver failure.
Write-Section '3. Failed USB enumerations ("Unknown USB Device")'
$Unknown = @($AllDevices | Where-Object { $_.InstanceId -match 'VID_0000' -or ($_.FriendlyName -and $_.FriendlyName -match $UnknownPattern) })
$UnknownPresent = @($Unknown | Where-Object { $PresentIds.Contains($_.InstanceId) })
if ($Unknown.Count -eq 0) {
    Write-Finding OK 'USB' 'No "Unknown USB Device" entries exist - Windows holds no record of a failed USB enumeration.'
}
else {
    foreach ($u in $Unknown) {
        $state = if ($PresentIds.Contains($u.InstanceId)) { 'PRESENT' } else { 'not connected' }
        $props = Get-DevProps $u.InstanceId
        $loc   = Get-PropValue $props 'DEVPKEY_Device_LocationPaths'
        $arr   = Get-PropValue $props 'DEVPKEY_Device_LastArrivalDate'
        Write-Host ("  {0}  [{1}]" -f $u.FriendlyName, $state) -ForegroundColor White
        Write-Detail "Instance: $($u.InstanceId)"
        if ($loc) { Write-Detail "Port    : $(@($loc)[0])" }
        if ($arr) { Write-Detail "Last seen arriving: $arr" }
    }
    Write-Finding Warn 'USB' "Windows has recorded $($Unknown.Count) failed USB enumeration(s) ($($UnknownPresent.Count) present now)." `
        'A device connected but did not answer the descriptor request. If the timing matches a K7 switch-on, the K7 attached before its USB receiver was ready, or the cable/port/hub dropped the link.'
}

# ---------------------------------------------------------------------------
# 4. USB path
# ---------------------------------------------------------------------------
# Trace the K7 up through its hubs to the host controller. A hub that is a separate
# device (front panel, dock, monitor) is a common cause of flaky enumeration; a hub
# built into the motherboard is normal. Built-in devices carry a special container ID.
Write-Section '4. USB path from the K7 to the controller'
$UsbControllers = @($AllDevices | Where-Object { $PresentIds.Contains($_.InstanceId) -and $_.Class -eq 'USB' -and $_.FriendlyName -match 'Host Controller|xHCI|eXtensible' })
foreach ($c in $UsbControllers) {
    $vendor = 'Other'
    if ($c.InstanceId -match 'VEN_8086') { $vendor = 'Intel' }
    elseif ($c.InstanceId -match 'VEN_1B21') { $vendor = 'ASMedia' }
    elseif ($c.InstanceId -match 'VEN_1022') { $vendor = 'AMD' }
    Write-Detail "Controller: $($c.FriendlyName) [$vendor] $($c.InstanceId)"
}

$ExternalHub = $false
$HubLinks = @()
$HubVendors = @{ '05E3' = 'Genesys Logic'; '2109' = 'VIA Labs'; '0BDA' = 'Realtek'; '1A40' = 'Terminus Technology'; '0451' = 'Texas Instruments'; '0424' = 'Microchip/SMSC'; '174C' = 'ASMedia'; '8087' = 'Intel' }
if ($K7RootsPresent.Count -gt 0) {
    $root  = $K7RootsPresent[0]
    $props = Get-DevProps $root.InstanceId
    $loc   = Get-PropValue $props 'DEVPKEY_Device_LocationPaths'
    if ($loc) { Write-Detail "K7 port location: $(@($loc)[0])" }
    $chain = @(Get-ParentChain $root.InstanceId)
    $K7ChainForFix = @($chain)
    $indent = '  '
    Write-Host "  $($root.FriendlyName)" -ForegroundColor White
    $MachineContainer = '00000000-0000-0000-ffff-ffffffffffff'   # container ID Windows gives non-removable, built-in devices
    $ExternalHubs = @()
    $BuiltInHubs  = @()
    foreach ($link in $chain) {
        $indent += '  '
        Write-Host "$indent<- $($link.Name)  ($($link.InstanceId))" -ForegroundColor Gray
        if ($link.InstanceId -match '^USB\\VID_' -and $link.Name -match 'Hub') {
            $HubLinks += $link
            $cid = $null
            $cp = Get-PnpDeviceProperty -InstanceId $link.InstanceId -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction SilentlyContinue
            if ($cp) { $cid = $cp.Data }
            if (("$cid").Trim("{}") -eq $MachineContainer) { $BuiltInHubs += $link } else { $ExternalHubs += $link }
        }
    }
    $ExternalHub = ($ExternalHubs.Count -gt 0)
    foreach ($h in $HubLinks) {
        $m = [regex]::Match($h.InstanceId, 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})')
        if ($m.Success) {
            $vn = 'unknown vendor'
            if ($HubVendors.ContainsKey($m.Groups[1].Value)) { $vn = $HubVendors[$m.Groups[1].Value] }
            $kind = if ($BuiltInHubs -contains $h) { 'built into this PC' } else { 'separate device' }
            Write-Detail "Hub: $($h.Name) - $vn, VID $($m.Groups[1].Value) PID $($m.Groups[2].Value), $kind"
        }
    }
    if ($ExternalHub) {
        Write-Finding Warn 'USB' 'The K7 connects through a USB hub that is a separate device (front panel, monitor, dock or standalone hub).' `
            'FiiO advises a rear motherboard port; move the K7 and re-run until the path shows "USB Root Hub" or only a built-in hub above the K7.'
    }
    elseif ($BuiltInHubs.Count -gt 0) {
        Write-Finding Info 'USB' 'The K7 sits behind a hub built into the PC (typical of the motherboard rear I/O panel).' `
            'This is normal on many boards and not a fault. Only if the port is a case front-panel header would a rear port be preferable.'
    }
    else {
        Write-Finding OK 'USB' 'The K7 connects directly to a motherboard root hub port (no intermediate hub detected).'
    }
}
else {
    Write-Detail 'The K7 is not connected, so its USB path cannot be traced. Run again with the K7 working to see it.'
}

# ---------------------------------------------------------------------------
# 5. Power management
# ---------------------------------------------------------------------------
# Windows power saving can suspend USB ports or hubs and leave a device that
# attaches at the wrong moment unanswered. Check the power plan, Fast Startup and
# the per-device "turn off to save power" flags on the K7's path.
Write-Section '5. Power management'
$SchemeGuid = Get-ActiveSchemeGuid
$SchemeName = Get-ActiveSchemeName
Write-Detail "Active power plan: $(if ($SchemeName) { $SchemeName + ' ' })$SchemeGuid"

$ss = Get-PowerSetting $GUID_SUB_USB $GUID_USB_SS
$UsbSelectiveSuspendOn = ($ss.AC -eq 1)
if ($null -eq $ss.AC) {
    Write-Finding Info 'Power' 'Could not read the USB selective suspend setting (non-English Windows or hidden setting).'
}
elseif ($UsbSelectiveSuspendOn) {
    Write-Finding Warn 'Power' 'USB selective suspend is ENABLED on mains power.' `
        'Windows can suspend idle USB ports and hubs, which can disrupt a device that attaches while the hub is idle. -Fix disables it.'
}
else {
    Write-Finding OK 'Power' 'USB selective suspend is disabled on mains power.'
}

$ls = Get-PowerSetting $GUID_SUB_PCIE $GUID_PCIE_LSPM
$LspmOn = ($null -ne $ls.AC -and $ls.AC -gt 0)
if ($LspmOn) {
    Write-Finding Warn 'Power' "PCI Express Link State Power Management is ON (level $($ls.AC)) on mains power." `
        'This can let the USB controller drop into a low-power link state. -Fix turns it off (a desktop loses nothing meaningful).'
}
elseif ($null -ne $ls.AC) {
    Write-Finding OK 'Power' 'PCI Express Link State Power Management is off on mains power.'
}

$usbSvcDisable = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\USB' 'DisableSelectiveSuspend'
if ($null -ne $usbSvcDisable) { Write-Detail "Global USB DisableSelectiveSuspend = $usbSvcDisable" }

$Hiberboot   = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
$HibernateOn = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled'
if ($null -eq $HibernateOn) { $HibernateOn = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' }
$FastStartupOn = ($Hiberboot -eq 1 -and $HibernateOn -ne 0)
if ($FastStartupOn) {
    Write-Finding Info 'Power' 'Fast Startup is ENABLED.' `
        'Only relevant if the K7 fails after a cold boot with the K7 already switched on: Windows resumes a saved USB state instead of re-enumerating cleanly.'
}
else {
    Write-Finding OK 'Power' 'Fast Startup is disabled.'
}

# Per-device "allow the computer to turn off this device"
$MSPower = @(Get-MSPowerEntries)
$RootHubs = @($AllDevices | Where-Object { $PresentIds.Contains($_.InstanceId) -and $_.InstanceId -like 'USB\ROOT_HUB*' })
$PowerTargets = @()
$PowerTargets += $RootHubs
$PowerTargets += @($K7ChainForFix | ForEach-Object { Get-PnpDevice -InstanceId $_.InstanceId -ErrorAction SilentlyContinue })
$PowerTargets += $K7RootsPresent
$PowerTargets = @($PowerTargets | Where-Object { $_ } | Sort-Object InstanceId -Unique)
$TurnOffAllowed = @()
if ($MSPower.Count -eq 0) {
    Write-Detail 'Device power-management flags unavailable (needs administrator rights).'
}
else {
    foreach ($t in $PowerTargets) {
        $e = Find-MSPowerEntry $MSPower $t.InstanceId
        if ($e -and $e.Enable) { $TurnOffAllowed += $t }
    }
    if ($TurnOffAllowed.Count -gt 0) {
        Write-Finding Warn 'Power' "$($TurnOffAllowed.Count) USB hub/device(s) on the K7's path allow Windows to turn them off to save power." `
            '-Fix clears "Allow the computer to turn off this device to save power" on these.'
        foreach ($t in $TurnOffAllowed) { Write-Detail "$($t.FriendlyName) ($($t.InstanceId))" }
    }
    else {
        Write-Finding OK 'Power' 'No hub or device on the K7 path is allowed to power down.'
    }
}

$K7RegFlags = @()
foreach ($r in $K7Roots) {
    $dp = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($r.InstanceId)\Device Parameters"
    foreach ($n in 'EnhancedPowerManagementEnabled', 'SelectiveSuspendEnabled', 'AllowIdleIrpInD3') {
        $v = Get-RegDword $dp $n
        if ($null -ne $v) {
            Write-Detail "$($r.InstanceId): $n = $v"
            if ($v -ne 0) { $K7RegFlags += $n }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Event logs
# ---------------------------------------------------------------------------
# Search the Kernel-PnP and System logs for the K7 or Unknown USB Devices.
# Event 411 = a device driver failed to start. Event 400/410 = device configured/started.
# If the K7 clearly arrived but no events exist, the log is "blind" (not elevated or
# disabled), and the absence of failures cannot be trusted.
Write-Section "6. Event logs (last $Days days)"
$Since = (Get-Date).AddDays(-$Days)
$PnpEvents = @()
$PnpAll = @()
try {
    $PnpAll = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; StartTime = $Since } -ErrorAction Stop)
}
catch { Write-Detail "Kernel-PnP/Configuration log unavailable: $($_.Exception.Message)" }
Write-Detail "Kernel-PnP/Configuration events in the window (all devices): $($PnpAll.Count)"
if ($PnpAll.Count -gt 0) {
    Write-Detail ("Oldest: {0:yyyy-MM-dd HH:mm}   Newest: {1:yyyy-MM-dd HH:mm}" -f ($PnpAll | Select-Object -Last 1).TimeCreated, ($PnpAll | Select-Object -First 1).TimeCreated)
}
$PnpEvents = @($PnpAll | Where-Object { $t = Get-EventText $_; ($t -match $K7IdPattern) -or ($t -match 'VID_0000') })

$K7StartFailures   = @($PnpEvents | Where-Object { $_.Id -eq 411 -and (Get-EventText $_) -match $K7IdPattern })
$K7Configured      = @($PnpEvents | Where-Object { $_.Id -in 400, 410 -and (Get-EventText $_) -match $K7IdPattern })
$UnknownEvents     = @($PnpEvents | Where-Object { (Get-EventText $_) -match 'VID_0000' })

$K7Arrival = $null
foreach ($r in $K7RootsPresent) {
    $a = Get-PropValue (Get-DevProps $r.InstanceId) 'DEVPKEY_Device_LastArrivalDate'
    if ($a -and (-not $K7Arrival -or $a -gt $K7Arrival)) { $K7Arrival = $a }
}
$BootTime = $null
$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($osInfo) { $BootTime = $osInfo.LastBootUpTime; Write-Detail ("Last Windows boot: {0:yyyy-MM-dd HH:mm:ss}" -f $BootTime) }
if ($K7Arrival -and $BootTime) {
    $lag = [math]::Round(($K7Arrival - $BootTime).TotalMinutes, 1)
    if ($lag -gt 2) { Write-Detail "K7 last arrived $lag min AFTER boot (switched on or re-plugged while Windows was running)." }
    else            { Write-Detail "K7 last arrived at boot (it was already on when Windows started)." }
}
$EventLogBlind = ($K7Arrival -and $K7Arrival -gt $Since -and $K7Configured.Count -eq 0)
Write-Detail "K7 configure/start events : $($K7Configured.Count)"
Write-Detail "K7 start FAILURES (411)   : $($K7StartFailures.Count)"
Write-Detail "Unknown USB device events : $($UnknownEvents.Count)"

foreach ($ev in ($PnpEvents | Select-Object -First 25)) {
    Write-Detail ("{0:yyyy-MM-dd HH:mm:ss}  ID {1}  {2}" -f $ev.TimeCreated, $ev.Id, (Get-ShortMessage $ev.Message 160))
}

if ($K7StartFailures.Count -gt 0) {
    Write-Finding Fault 'Events' "Windows logged $($K7StartFailures.Count) failure(s) to START the K7 driver." `
        'Windows saw the K7 but its driver would not start: a Windows/driver problem, not hardware.'
}
if ($UnknownEvents.Count -gt 0) {
    Write-Finding Warn 'Events' "Windows logged $($UnknownEvents.Count) event(s) for an Unknown USB Device (failed enumeration)." `
        'Compare the times above with when the K7 failed. A match points to the USB link (K7 start-up, cable, port), not the driver.'
}

if ($EventLogBlind) {
    Write-Finding Info 'Events' 'The K7 arrived within this window, yet no configure event for it was found.' `
        'The Kernel-PnP log is not capturing this device (not elevated, log cleared or disabled), so "no events" does not prove Windows saw nothing.'
}

# Get-WinEvent fails the whole query if ANY listed provider is not registered on this
# PC (e.g. "usbhub"), so keep only the providers that actually exist.
$SysEvents = @()
$wantedProviders = 'Microsoft-Windows-Kernel-PnP', 'Microsoft-Windows-UserPnp', 'Microsoft-Windows-USB-USBHUB3', 'usbhub', 'usbhub3', 'Microsoft-Windows-USB-USBXHCI'
$sysProviders = @($wantedProviders | Where-Object { Get-WinEvent -ListProvider $_ -ErrorAction SilentlyContinue })
if ($sysProviders.Count -gt 0) {
    try {
        $SysEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Since; ProviderName = $sysProviders } -ErrorAction Stop |
            Where-Object { (Get-EventText $_) -match $K7IdPattern -or (Get-EventText $_) -match 'VID_0000' -or (Get-EventText $_) -match 'FiiO' })
    }
    catch { }
}
if ($SysEvents.Count -gt 0) {
    Write-Detail "System log entries mentioning the K7 or unknown USB devices: $($SysEvents.Count)"
    foreach ($ev in ($SysEvents | Select-Object -First 10)) {
        Write-Detail ("{0:yyyy-MM-dd HH:mm:ss}  {1} {2}  {3}" -f $ev.TimeCreated, $ev.ProviderName, $ev.Id, (Get-ShortMessage $ev.Message 140))
    }
}

# ---------------------------------------------------------------------------
# 7. Drivers, audio stack and audio software
# ---------------------------------------------------------------------------
# List FiiO driver packages in the driver store (via pnputil), confirm the Windows
# audio services are running, check that the K7 produced an audio endpoint, and
# flag any audio enhancement software that could interfere.
Write-Section '7. Drivers, audio services and audio software'
$pnpDrivers = & pnputil.exe /enum-drivers 2>$null
$FiioPackages = @()
if ($pnpDrivers) {
    $blocks = (($pnpDrivers -join "`n") -split "`n\s*`n")
    foreach ($blk in $blocks) {
        if ($blk -match 'FiiO|Thesycon|XMOS') {
            $pub  = [regex]::Match($blk, 'Published Name:\s*(\S+)').Groups[1].Value
            $orig = [regex]::Match($blk, 'Original Name:\s*(\S+)').Groups[1].Value
            $prov = [regex]::Match($blk, 'Provider Name:\s*(.+)').Groups[1].Value.Trim()
            $ver  = [regex]::Match($blk, 'Driver Version:\s*(.+)').Groups[1].Value.Trim()
            $FiioPackages += [pscustomobject]@{ Published = $pub; Original = $orig; Provider = $prov; Version = $ver }
        }
    }
}
if ($FiioPackages.Count -gt 0) {
    foreach ($p in $FiioPackages) { Write-Detail "Driver package: $($p.Published) ($($p.Original)) $($p.Provider) $($p.Version)" }
    if ($FiioPackages.Count -gt 2) {
        Write-Finding Info 'Driver' "$($FiioPackages.Count) FiiO/Thesycon driver packages sit in the driver store." `
            'Several versions can co-exist; if you suspect the driver, uninstall the FiiO USB DAC driver, remove old packages, then install the current one from FiiO.'
    }
}
else {
    Write-Detail 'No FiiO/Thesycon driver package in the driver store (the K7 uses the Windows in-box driver).'
}

$uninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$apps = @(Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName })
foreach ($a in ($apps | Where-Object { $_.DisplayName -match 'FiiO|Thesycon' })) {
    $dv = $a.PSObject.Properties['DisplayVersion']
    Write-Detail "Installed: $($a.DisplayName) $(if ($dv) { $dv.Value })"
}

foreach ($svcName in 'Audiosrv', 'AudioEndpointBuilder') {
    $s = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Running') {
        Write-Finding Fault 'Audio' "Windows audio service $svcName is $($s.Status)." 'Start it (or restart Windows); no USB audio device can appear without it.'
    }
}

$Endpoints = @($AllDevices | Where-Object { $_.Class -eq 'AudioEndpoint' -and $PresentIds.Contains($_.InstanceId) -and $_.FriendlyName -match 'FiiO|K7' })
if ($Endpoints.Count -gt 0) {
    foreach ($e in $Endpoints) { Write-Detail "Audio endpoint: $($e.FriendlyName) [$($e.Status)]" }
}
elseif ($K7PresentOK) {
    Write-Finding Warn 'Audio' 'The K7 USB device works, yet no FiiO audio endpoint is present.' `
        'The failure sits in the Windows audio stack or an audio enhancement layer, not USB.'
}

$swHits = @()
$swHits += @($apps | Where-Object { $_.DisplayName -match $AudioSwPattern } | ForEach-Object { "App: $($_.DisplayName)" })
$swHits += @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' -and ($_.DisplayName -match $AudioSwPattern -or $_.Name -match $AudioSwPattern) } | ForEach-Object { "Service: $($_.DisplayName)" })
$swHits = @($swHits | Sort-Object -Unique)
if ($swHits.Count -gt 0) {
    Write-Finding Info 'Software' "Found $($swHits.Count) audio utility/enhancement component(s) that hook into the audio stack." `
        'Usually innocent, but worth testing without them (FiiO users have traced K7 detection problems to software conflicts). ASUS Sonic Studio/Armoury Crate ships with ROG boards.'
    foreach ($h in $swHits) { Write-Detail $h }
}

# ---------------------------------------------------------------------------
# 8. Live capture
# ---------------------------------------------------------------------------
# With -Watch, subscribe to WMI device create/delete/modify events, let the user
# switch the K7 on, and log everything Windows reports for the capture window.
# The result is classified A-D (see the .DESCRIPTION at the top of the script).
$Capture = $null
if (-not $Watch) {
    Write-Section '8. Live capture'
    Write-Detail 'Skipped. Run with -Watch and switch the K7 on to record what Windows sees at that moment.'
}
if ($Watch) {
    Write-Section '8. Live capture: what Windows sees when the K7 switches on'
    Write-Host '  1. Make sure the K7 is switched OFF.' -ForegroundColor White
    Write-Host '     For a faithful test, leave it off as long as it normally sits off (the failure' -ForegroundColor White
    Write-Host '     tends to follow a cold switch-on, not a quick off/on).' -ForegroundColor White
    Write-Host '  2. Press Enter, then switch the K7 ON within 10 seconds and leave it alone.' -ForegroundColor White
    Write-Host "  3. The capture runs for $WatchSeconds seconds." -ForegroundColor White
    [void](Read-Host '  Press Enter to start')

    $srcIds = 'K7W_Create', 'K7W_Delete', 'K7W_Modify'
    foreach ($s in $srcIds) { Unregister-Event -SourceIdentifier $s -ErrorAction SilentlyContinue }
    Get-Event -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue

    $CaptureStart = Get-Date
    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity'" -SourceIdentifier 'K7W_Create' | Out-Null
    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity'" -SourceIdentifier 'K7W_Delete' | Out-Null
    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.PNPDeviceID LIKE 'USB%'" -SourceIdentifier 'K7W_Modify' | Out-Null

    Write-Host '  Capturing... switch the K7 ON now.' -ForegroundColor Green
    $log = New-Object System.Collections.Generic.List[object]
    $deadline = $CaptureStart.AddSeconds($WatchSeconds)
    while ((Get-Date) -lt $deadline) {
        $evt = Wait-Event -Timeout 1
        if (-not $evt) { continue }
        if ($srcIds -contains $evt.SourceIdentifier) {
            $ti = $evt.SourceEventArgs.NewEvent.TargetInstance
            $kind = switch ($evt.SourceIdentifier) { 'K7W_Create' { 'Arrived' } 'K7W_Delete' { 'Removed' } default { 'Changed' } }
            $rec = [pscustomobject]@{
                Time      = $evt.TimeGenerated
                Event     = $kind
                Name      = $ti.Name
                DeviceId  = $ti.PNPDeviceID
                Status    = $ti.Status
                ErrorCode = $ti.ConfigManagerErrorCode
            }
            $log.Add($rec)
            $colour = 'Gray'
            if ($rec.DeviceId -match $K7IdPattern) { $colour = 'Green' }
            if ($rec.DeviceId -match 'VID_0000' -or ($rec.ErrorCode -and $rec.ErrorCode -ne 0)) { $colour = 'Red' }
            Write-Host ("    +{0,5:N1}s  {1,-8} {2}  [{3}, code {4}]" -f ($rec.Time - $CaptureStart).TotalSeconds, $rec.Event, $rec.Name, $rec.Status, $rec.ErrorCode) -ForegroundColor $colour
        }
        Remove-Event -EventIdentifier $evt.EventIdentifier -ErrorAction SilentlyContinue
    }
    foreach ($s in $srcIds) { Unregister-Event -SourceIdentifier $s -ErrorAction SilentlyContinue }

    # Kernel-PnP log for the same window (catches anything the WMI poll missed)
    $capPnp = @()
    try {
        $capPnp = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; StartTime = $CaptureStart } -ErrorAction Stop |
            Where-Object { (Get-EventText $_) -match 'USB\\' })
    }
    catch { }
    if ($capPnp.Count -gt 0) {
        Write-Host '  Kernel-PnP log during the capture:' -ForegroundColor Gray
        foreach ($ev in ($capPnp | Sort-Object TimeCreated)) {
            Write-Detail ("{0:HH:mm:ss}  ID {1}  {2}" -f $ev.TimeCreated, $ev.Id, (Get-ShortMessage $ev.Message 150))
        }
    }

    # Post-capture state
    $nowK7 = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match $K7IdPattern })
    $nowK7Bad = @($nowK7 | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })
    $nowEndpoints = @(Get-PnpDevice -PresentOnly -Class AudioEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'FiiO|K7' })

    $usbArrivals = @($log | Where-Object { $_.Event -eq 'Arrived' -and $_.DeviceId -like 'USB*' })
    $k7Seen      = @($log | Where-Object { $_.DeviceId -match $K7IdPattern }) + @($capPnp | Where-Object { (Get-EventText $_) -match $K7IdPattern })
    $unkSeen     = @($log | Where-Object { $_.DeviceId -match 'VID_0000' -or $_.Name -match $UnknownPattern -or $_.ErrorCode -eq 43 }) +
                   @($capPnp | Where-Object { (Get-EventText $_) -match 'VID_0000' })
    $k7Failed    = @($capPnp | Where-Object { $_.Id -eq 411 -and (Get-EventText $_) -match $K7IdPattern })

    # Classify the attempt. Order matters: the most specific, Windows-side outcomes are
    # tested first and "nothing attached at all" (A) is only concluded when no USB
    # activity of any kind was seen.
    $verdict = $null
    if ($nowK7.Count -gt 0 -and $nowK7Bad.Count -eq 0 -and $nowEndpoints.Count -gt 0) {
        $verdict = 'OK'
        Write-Finding OK 'Capture' 'The K7 was recognised correctly this time (USB device and audio endpoint both present).' `
            'The fault did not reproduce. Run -Watch again on an occasion when it normally fails (for example the first switch-on of the day).'
    }
    elseif ($nowK7Bad.Count -gt 0 -or $k7Failed.Count -gt 0) {
        $verdict = 'C'
        $code = if ($nowK7Bad.Count -gt 0) { $nowK7Bad[0].ConfigManagerErrorCode } else { '?' }
        Write-Finding Fault 'Capture' "RESULT C: Windows saw the K7 but could not start it (Code $code - $(if ("$code" -ne '?') { Get-ProblemText ([int]$code) } else { 'see log' }))." `
            'WINDOWS-SIDE fault: driver or the open USB audio known issue. Hardware is fine.'
    }
    elseif ($nowK7.Count -gt 0 -and $nowEndpoints.Count -eq 0) {
        $verdict = 'D'
        Write-Finding Fault 'Capture' 'RESULT D: the K7 USB device started, but no audio output device appeared.' `
            'WINDOWS-SIDE fault in the audio stack (Audio Endpoint Builder or an audio enhancement/APO). Test with audio utilities removed.'
    }
    elseif ($unkSeen.Count -gt 0) {
        $verdict = 'B'
        Write-Finding Fault 'Capture' 'RESULT B: a USB device attached but failed enumeration (Unknown USB Device / descriptor request failed).' `
            'LINK-LEVEL fault: the K7 attached to USB before its USB receiver could answer, or the cable/port/hub corrupted the exchange. Windows reported it correctly.'
    }
    elseif ($usbArrivals.Count -eq 0 -and $k7Seen.Count -eq 0) {
        $verdict = 'A'
        Write-Finding Fault 'Capture' 'RESULT A: Windows saw NO USB attach at all when the K7 switched on.' `
            'HARDWARE-PATH fault: the K7 never signalled a connection. Check INPUT is on USB, try another cable and a rear USB 2.0 port; if it persists, the K7 itself is at fault.'
    }
    else {
        $verdict = 'Unclear'
        Write-Finding Warn 'Capture' 'USB activity occurred but the K7 did not end up present. See the event list above.' `
            'Send the report to FiiO support with the capture section.'
    }
    $Capture = [pscustomobject]@{ Verdict = $verdict; Events = $log }
}

# ---------------------------------------------------------------------------
# 9. Verdict
# ---------------------------------------------------------------------------
# Combine the live capture result (if any) with the evidence from sections 2-6 into
# a plain-language conclusion: Windows side, USB link side, or most likely hardware.
Write-Section '9. Verdict'
$WindowsSide = ($K7StartFailures.Count -gt 0) -or ($null -ne $K7PresentError) -or ($AffectedBuild -and $K7Mode -eq 'UAC1' -and $K7PresentError -eq 10)
$LinkSide    = ($UnknownEvents.Count -gt 0) -or ($Unknown.Count -gt 0)

if ($Capture -and $Capture.Verdict -ne 'OK' -and $Capture.Verdict -ne 'Unclear') {
    switch ($Capture.Verdict) {
        'A' { Write-Host '  The live capture shows the K7 never attached. Cause: K7 / cable / port, not Windows.' -ForegroundColor Red }
        'B' { Write-Host '  The live capture shows a failed USB enumeration. Cause: USB link start-up (K7 timing, cable, port or hub).' -ForegroundColor Red }
        'C' { Write-Host '  The live capture shows Windows rejecting the K7 driver start. Cause: Windows / driver.' -ForegroundColor Red }
        'D' { Write-Host '  The live capture shows the audio endpoint missing. Cause: Windows audio stack or audio software.' -ForegroundColor Red }
    }
}
elseif ($WindowsSide) {
    Write-Host '  Evidence points to WINDOWS: it saw the K7 and failed to start its driver.' -ForegroundColor Red
}
elseif ($LinkSide) {
    Write-Host '  Evidence points to the USB LINK: Windows recorded failed enumerations (Unknown USB Device),' -ForegroundColor Yellow
    Write-Host '  not driver failures. The K7 connects, but does not answer correctly on the first attempt.' -ForegroundColor Yellow
    Write-Host '  A second switch-on gives Windows a fresh attach, which is why the off/on cycle works.' -ForegroundColor Yellow
}
elseif ($EventLogBlind) {
    Write-Host '  No failure is recorded, but the event log did not capture even the K7''s successful attach,' -ForegroundColor Yellow
    Write-Host '  so its silence is not proof. Run -Watch (elevated) at the moment the K7 fails for real evidence.' -ForegroundColor Yellow
}
else {
    Write-Host '  Windows holds no record of a failed start or failed enumeration for the K7.' -ForegroundColor Yellow
    Write-Host '  When the K7 fails, Windows most likely never sees it attach at all. That points to the K7' -ForegroundColor Yellow
    Write-Host '  (its USB receiver not starting up on the first power-on), the cable, or the port rather than' -ForegroundColor Yellow
    Write-Host '  Windows. Run with -Watch at the moment it fails to confirm.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Ruling hardware in or out:' -ForegroundColor White
Write-Host '   1. Connect the K7 directly to a REAR motherboard USB port (try a USB 2.0 port if the board has one).'
Write-Host '   2. Use a different, short USB-B cable.'
Write-Host '   3. Test the K7 on another computer (or a phone/tablet with an adapter) with a cold switch-on.'
Write-Host '      Fails there too -> K7 hardware/firmware: contact FiiO or the retailer under warranty.'
Write-Host '      Works there     -> this PC: apply -Fix, then work through the Windows items above.'

$counts = $Findings | Group-Object Level | ForEach-Object { "$($_.Name): $($_.Count)" }
Write-Host ''
Write-Host ('  Findings - ' + ($counts -join ', ')) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 10. Fixes
# ---------------------------------------------------------------------------
# Only runs with -Fix. Every change is confirmed first and its previous value is
# written to the backup JSON so -RestoreFrom can undo it. Nothing here touches
# firmware, drivers or Windows updates.
if ($Fix) {
    Write-Section '10. Fixes'
    Write-Host "  Each change is recorded in $BackupPath so -RestoreFrom can undo it." -ForegroundColor Gray
    $Backup = [ordered]@{
        Created    = (Get-Date).ToString('s')
        SchemeGuid = $SchemeGuid
        Power      = New-Object System.Collections.Generic.List[object]
        Registry   = New-Object System.Collections.Generic.List[object]
        MSPower    = New-Object System.Collections.Generic.List[object]
    }

    # Writes the backup to disk after every change so a crash mid-run loses nothing
    function Save-Backup {
        $Backup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $BackupPath -Encoding UTF8
    }

    # Sets a registry DWORD, first recording its old value (or that it did not exist)
    function Set-RegDwordWithBackup {
        param([string]$Path, [string]$Name, [int]$Value)
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $old = Get-RegDword $Path $Name
        try {
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            $Backup.Registry.Add([pscustomobject]@{ Path = $Path; Name = $Name; Existed = ($null -ne $old); Value = $old })
            Save-Backup
            return $true
        }
        catch {
            Write-Host "    Could not set $Path\$Name : $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }

    # F1 + F2: power plan settings
    $planChanged = $false
    if ($UsbSelectiveSuspendOn -or ($null -ne $ss.DC -and $ss.DC -eq 1)) {
        if (Confirm-Step 'Disable USB selective suspend in the active power plan?') {
            $Backup.Power.Add([pscustomobject]@{ Name = 'USB selective suspend'; Sub = $GUID_SUB_USB; Setting = $GUID_USB_SS; AC = $ss.AC; DC = $ss.DC })
            & powercfg.exe /setacvalueindex SCHEME_CURRENT $GUID_SUB_USB $GUID_USB_SS 0 | Out-Null
            & powercfg.exe /setdcvalueindex SCHEME_CURRENT $GUID_SUB_USB $GUID_USB_SS 0 | Out-Null
            $planChanged = $true
            Write-Host '    USB selective suspend disabled.' -ForegroundColor Green
        }
    }
    if ($LspmOn) {
        if (Confirm-Step 'Turn off PCI Express Link State Power Management?') {
            $Backup.Power.Add([pscustomobject]@{ Name = 'PCIe LSPM'; Sub = $GUID_SUB_PCIE; Setting = $GUID_PCIE_LSPM; AC = $ls.AC; DC = $ls.DC })
            & powercfg.exe /setacvalueindex SCHEME_CURRENT $GUID_SUB_PCIE $GUID_PCIE_LSPM 0 | Out-Null
            & powercfg.exe /setdcvalueindex SCHEME_CURRENT $GUID_SUB_PCIE $GUID_PCIE_LSPM 0 | Out-Null
            $planChanged = $true
            Write-Host '    PCIe Link State Power Management off.' -ForegroundColor Green
        }
    }
    if ($planChanged) { & powercfg.exe /setactive SCHEME_CURRENT | Out-Null; Save-Backup }

    # F3: device power management on hubs and the K7
    if ($TurnOffAllowed.Count -gt 0) {
        if (Confirm-Step "Stop Windows turning off $($TurnOffAllowed.Count) USB hub/device(s) to save power?") {
            foreach ($t in $TurnOffAllowed) {
                $e = Find-MSPowerEntry $MSPower $t.InstanceId
                if ($e) {
                    try {
                        $Backup.MSPower.Add([pscustomobject]@{ InstanceName = $e.InstanceName; Enable = [bool]$e.Enable })
                        Set-CimInstance -InputObject $e -Property @{ Enable = $false } -ErrorAction Stop
                        Write-Host "    $($t.FriendlyName): power-down disabled." -ForegroundColor Green
                    }
                    catch { Write-Host "    $($t.FriendlyName): $($_.Exception.Message)" -ForegroundColor Yellow }
                }
            }
            Save-Backup
        }
    }
    if ($K7Roots.Count -gt 0) {
        $pending = @()
        foreach ($r in $K7Roots) {
            $dp = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($r.InstanceId)\Device Parameters"
            if (-not (Test-Path -LiteralPath $dp)) { continue }
            foreach ($n in 'EnhancedPowerManagementEnabled', 'SelectiveSuspendEnabled', 'AllowIdleIrpInD3') {
                $v = Get-RegDword $dp $n
                # Only the core flag is worth creating; the others matter only when a driver already set them
                if (($n -eq 'EnhancedPowerManagementEnabled' -and $v -ne 0) -or ($n -ne 'EnhancedPowerManagementEnabled' -and $null -ne $v -and $v -ne 0)) {
                    $pending += [pscustomobject]@{ Path = $dp; Name = $n; Id = $r.InstanceId }
                }
            }
        }
        if ($pending.Count -gt 0 -and (Confirm-Step 'Disable selective suspend / idle power-down flags on the K7 device entries?')) {
            foreach ($x in $pending) {
                if (Set-RegDwordWithBackup $x.Path $x.Name 0) { Write-Host "    $($x.Id): $($x.Name) = 0" -ForegroundColor Green }
            }
        }
    }

    # F4: phantom devices
    $Stale = @()
    $Stale += @($K7Phantoms | Where-Object { $_.Class -ne 'AudioEndpoint' -and $_.InstanceId -like 'USB*' })
    $Stale += @($Unknown | Where-Object { -not $PresentIds.Contains($_.InstanceId) })
    $Stale = @($Stale | Sort-Object InstanceId -Unique)
    if ($Stale.Count -gt 0 -and $Build -ge 19041) {
        if (Confirm-Step "Remove $($Stale.Count) disconnected K7 / Unknown USB Device entries (Windows recreates them on next connect)?") {
            foreach ($s in $Stale) {
                $out = & pnputil.exe /remove-device "$($s.InstanceId)" 2>&1
                Write-Host "    $($s.InstanceId): $(($out | Select-Object -Last 1))" -ForegroundColor Gray
            }
        }
    }

    # F5: Fast Startup
    if ($FastStartupOn) {
        if (Confirm-Step 'Disable Fast Startup? (only matters if the K7 fails after a cold boot)') {
            if (Set-RegDwordWithBackup 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0) {
                Write-Host '    Fast Startup disabled.' -ForegroundColor Green
            }
        }
    }

    # F6: restart a present-but-failed K7, then rescan
    $nowBad = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match $K7IdPattern -and $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })
    foreach ($nb in $nowBad) {
        if (Confirm-Step "Restart the failed device $($nb.FriendlyName)?") {
            & pnputil.exe /restart-device "$($nb.InstanceId)" | Out-Null
        }
    }
    & pnputil.exe /scan-devices | Out-Null
    Write-Host '    Hardware rescan triggered.' -ForegroundColor Gray

    # Advice that the script deliberately does not automate
    if ($AffectedBuild -and $K7Mode -eq 'UAC1') {
        Write-Host ''
        Write-Host '  Not automated: the K7 runs on usbaudio.sys (UAC 1.0), which Microsoft''s open Code 10 issue affects.' -ForegroundColor Yellow
        Write-Host '  Options: install the current FiiO USB DAC driver from fiio.com, or wait for the Microsoft fix.' -ForegroundColor Yellow
    }

    if (($Backup.Power.Count + $Backup.Registry.Count + $Backup.MSPower.Count) -gt 0) {
        Save-Backup
        Write-Host ''
        Write-Host "  Backup saved: $BackupPath" -ForegroundColor Green
        Write-Host "  Undo with:    .\Diagnose-FiiOK7.ps1 -RestoreFrom `"$BackupPath`"" -ForegroundColor Green
    }
    else {
        Write-Host '  No settings changed.' -ForegroundColor Gray
    }
    Write-Host '  Restart Windows, then test a cold switch-on of the K7 (ideally with -Watch).' -ForegroundColor White
}
elseif (@($Findings | Where-Object { $_.Level -in 'Warn', 'Fault' }).Count -gt 0) {
    Write-Host ''
    Write-Host '  Run again with -Fix to apply the available fixes, or -Watch to capture a failing switch-on.' -ForegroundColor White
}

Write-Host ''
Write-Host "Report saved: $ReportPath" -ForegroundColor Cyan
Stop-Transcript | Out-Null
