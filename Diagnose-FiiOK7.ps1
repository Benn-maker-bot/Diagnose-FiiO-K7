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
      * Pre-flight safety checks: Windows version, 64-bit PowerShell, administrator
        rights, a writable output folder, required Windows tools, pending restarts.
      * Windows build, Insider channel, and the open Microsoft known issue that stops
        some USB Audio Class 1.0 devices starting (Code 10) after the 8 September 2026
        update (KB5124008) and later builds.
      * Every K7 device instance (present and phantom), its driver, problem code,
        last arrival/removal time and the USB path back to the controller.
      * "Unknown USB Device" (VID_0000) entries that betray failed enumerations.
      * USB selective suspend, PCIe link state power management, Fast Startup and
        per-device "allow the computer to turn off this device" settings.
      * Kernel-PnP and System event logs for K7 start failures and failed enumerations.
      * FiiO driver packages, audio services, audio endpoints, audio enhancements, the
        audio driver's idle power-down settings and audio software that can interfere.

    Modes:
      (default)     Read-only report. Changes nothing.
      -Watch        Live capture: you switch the K7 on and the script records exactly
                    what Windows sees, then gives a verdict for that attempt.
      -Watch -Trace Live capture plus a low-level USB trace (ETW) that records each step
                    of the USB conversation, to pin down exactly where result B fails.
      -Fix          Applies fixes after asking about each one. Backs up first.
      -Fix -DryRun  Shows exactly what -Fix would change, without changing anything.
      -RestoreFrom  Reverts the changes recorded in a backup file.

    Every run writes three kinds of output to a "reports" folder next to the script
    (or -OutputFolder):
      * FiiO-K7-Report-<time>.txt  - a transcript of everything shown on screen
      * FiiO-K7-Log-<time>.log     - a detailed, timestamped log, including every command
                                     run, every system change and every error
      * FiiO-K7-Backup-<time>.json - (with -Fix) the original value of every setting changed
      * FiiO-K7-UsbTrace-<time>.etl - (with -Trace) the raw USB trace for FiiO / Microsoft

.PARAMETER Watch
    Live capture mode: record what Windows sees while you switch the K7 on.

.PARAMETER WatchSeconds
    Length of the live capture in seconds (15-600, default 60).

.PARAMETER Trace
    With -Watch, also record a low-level USB ETW trace. Needs administrator rights.

.PARAMETER Fix
    Offer each available fix with a Y/N prompt. Every change is backed up first.

.PARAMETER DryRun
    With -Fix or -RestoreFrom: show what would change, but change nothing.

.PARAMETER Force
    With -Fix or -RestoreFrom: answer "yes" to every prompt. The safety checks still apply.

.PARAMETER NoRestorePoint
    With -Fix: do not create a Windows System Restore point before the first change.

.PARAMETER Days
    How many days of event log history to search (1-90, default 14).

.PARAMETER RestoreFrom
    Path to a backup JSON created by -Fix. Reverts the changes recorded in it.

.PARAMETER OutputFolder
    Where reports, logs, backups and traces are written. Default: "reports" beside the script.

.EXAMPLE
    .\Diagnose-FiiOK7.ps1
    Read-only report.

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -Watch -Trace
    Leave the K7 off for as long as it normally sits off, then run this and switch it on
    when prompted. Run it again on a day it fails if the first attempt succeeds.

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -Fix -DryRun
    Preview every fix without changing anything.

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -Fix
    Report, then offer each fix in turn (relaunches elevated if needed).

.EXAMPLE
    .\Diagnose-FiiOK7.ps1 -RestoreFrom ".\reports\FiiO-K7-Backup-20261031-0800.json"

.NOTES
    HOW TO READ THIS SCRIPT (for beginners)
    ---------------------------------------
    PowerShell runs a script from top to bottom. This one is laid out as:
      1. param(...)          - the options you can pass on the command line
      2. Constants           - fixed values (device IDs, setting GUIDs, message text)
      3. Helper functions    - small reusable building blocks, defined before use
      4. Safety functions    - logging, backups, allow-lists, restore points
      5. The main body       - numbered sections 0-10 that run in order
      6. Clean-up            - always runs at the end, even after an error or Ctrl+C

    SAFETY RULES THIS SCRIPT FOLLOWS
    --------------------------------
      * Without -Fix or -RestoreFrom it only READS from the system.
      * Every change is asked about first (unless -Force) and can be previewed (-DryRun).
      * Before any change, the original value is written to a backup file and the file
        is verified. If the backup cannot be written, no change is made.
      * A System Restore point is created before the first change (unless -NoRestorePoint).
      * Changes are only allowed to an explicit allow-list of settings. Anything else,
        including a tampered backup file, is refused.
      * After every change the value is read back to confirm it took effect.
      * Only one copy of the script can make changes at a time.
      * It never installs or removes drivers, changes firmware or touches Windows Update.

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
    # With -Watch: also record a low-level USB (ETW) trace during the capture
    [switch]$Trace,
    # Offer to apply fixes (each one is confirmed individually and backed up first)
    [switch]$Fix,
    # Preview mode for -Fix / -RestoreFrom: report what would change, change nothing
    [switch]$DryRun,
    # Skip the Y/N prompts (only meaningful with -Fix or -RestoreFrom)
    [switch]$Force,
    # Do not create a System Restore point before the first change
    [switch]$NoRestorePoint,
    # How many days of event log history to search
    [ValidateRange(1, 90)]
    [int]$Days = 14,
    # Path to a backup JSON created by -Fix; reverts the changes it recorded
    [string]$RestoreFrom,
    # Where reports, logs and backups are written (defaults to a "reports" folder beside the script)
    [string]$OutputFolder = (Join-Path $PSScriptRoot 'reports')
)

# Strict mode turns use of unset variables and missing properties into errors, which
# catches typos early. 'Continue' keeps the script running when a single query fails:
# a diagnostic tool should report as much as it can rather than stop at the first
# problem. Every command that CHANGES something uses -ErrorAction Stop instead, so a
# failed change is always caught and reported.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# ===========================================================================
# Constants
# ===========================================================================
# Version of this script, written into logs and backups so they can be matched later
$ScriptVersion = '2.0.0'

# FiiO's USB vendor ID is 0x2972. XMOS (the K7's USB receiver chip) is 0x20B1;
# a K7 in firmware-update (DFU) mode or with generic firmware can show that ID.
$K7IdPattern      = 'VID_(2972|20B1)'                              # matches any instance ID or event text naming the K7's vendor
$K7NamePattern    = 'FiiO'                                         # fallback: match on the friendly name
$K7RootPattern    = '^USB\\VID_(2972|20B1)&PID_[0-9A-F]{4}\\'      # the top-level USB device node (not its audio child nodes)
# Strings that indicate a failed enumeration (the device attached but never described itself)
$UnknownPattern   = 'VID_0000|Unknown USB Device|Device Descriptor Request Failed|Port Reset Failed|Set Address Failed'
# Third-party audio utilities that insert themselves into the Windows audio stack
# and have been known to interfere with USB audio devices
$AudioSwPattern   = 'SonicStudio|Sonic Studio|ArmouryCrate|Armoury Crate|Nahimic|Voicemeeter|VB-Audio|SteelSeries|Sonar|FxSound|EqualizerAPO|Equalizer APO|Peace Equalizer|\bDTS\b|Dolby|Boom3D|Realtek Audio Console|RtkAudUService|Waves MaxxAudio|MaxxAudio|SoundSwitch|Wave Link|NVIDIA Broadcast|Krisp'

# Power-setting GUIDs used with powercfg.exe (a "sub" is the setting group, the other is the setting)
$GUID_SUB_USB     = '2a737441-1930-4402-8d77-b2bebba308a3'
$GUID_USB_SS      = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'   # USB selective suspend
$GUID_SUB_PCIE    = '501a4d13-42af-4429-9fd1-a8218c268e20'
$GUID_PCIE_LSPM   = 'ee12f906-d277-404b-b6da-e5fa1a576df5'   # PCIe Link State Power Management

# Windows audio endpoint property keys (stored as registry value names under each
# endpoint's "Properties" key). Read-only use: the script reports them, never sets them.
$PKEY_DisableEnhancements = '{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5'   # 1 = "Audio enhancements: Off"
$PKEY_ExclusiveAllow      = '{b3f8fa53-0004-438e-9003-51a46e139bfc},3'   # 0 = apps may NOT take exclusive control
$PKEY_ExclusivePriority   = '{b3f8fa53-0004-438e-9003-51a46e139bfc},4'   # 0 = exclusive apps do NOT get priority

# Low-level USB trace (ETW) settings. ETW ("Event Tracing for Windows") is the logging
# system built into Windows drivers. These three providers are the USB 3 stack that
# also handles USB 2 ports on modern PCs: the host controller (XHCI), the USB class
# extension (UCX) and the hub driver (USBHUB3), which runs device enumeration.
$EtwSessionName   = 'FiiOK7UsbTrace'
$EtwProviders     = @('Microsoft-Windows-USB-USBXHCI', 'Microsoft-Windows-USB-UCX', 'Microsoft-Windows-USB-USBHUB3')
$EtwMaxFileMB     = 256          # trace file size cap, so a forgotten trace can never fill the disk
$EtwMinFreeMB     = 1024         # refuse to start a trace with less free space than this

# ---------------------------------------------------------------------------
# SAFETY ALLOW-LISTS
# The ONLY things -Fix and -RestoreFrom are permitted to change. Every change is
# checked against these before it happens; anything else is refused and logged.
# This also protects against a backup file that has been edited or corrupted.
# ---------------------------------------------------------------------------
# Registry values: (path regex, allowed value names)
$AllowedRegistryTargets = @(
    @{  # K7 device parameters (only the K7's own USB device entries)
        PathPattern = '^HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB\\VID_(2972|20B1)&PID_[0-9A-F]{4}\\[^\\]+\\Device Parameters$'
        Names       = @('EnhancedPowerManagementEnabled', 'SelectiveSuspendEnabled', 'AllowIdleIrpInD3')
    },
    @{  # Fast Startup
        PathPattern = '^HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power$'
        Names       = @('HiberbootEnabled')
    }
)
# Power plan settings: (sub-group GUID, setting GUID)
$AllowedPowerSettings = @(
    @{ Sub = $GUID_SUB_USB;  Setting = $GUID_USB_SS },
    @{ Sub = $GUID_SUB_PCIE; Setting = $GUID_PCIE_LSPM }
)
# Device instance IDs pnputil may remove (only disconnected K7 or Unknown USB Device entries)
$AllowedRemovePattern  = '^USB\\VID_(2972|20B1|0000)&PID_[0-9A-F]{4}\\'
# Device instance IDs pnputil may restart (only the K7 itself)
$AllowedRestartPattern = $K7IdPattern

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

# ===========================================================================
# Parameter sanity checks
# ===========================================================================
# Catch combinations of options that do not make sense BEFORE anything runs, and
# explain them, rather than silently doing something the user did not intend.
if ($Fix -and $RestoreFrom) {
    Write-Host 'Use either -Fix or -RestoreFrom, not both in the same run.' -ForegroundColor Red
    exit 2
}
if ($Trace -and -not $Watch) {
    Write-Host 'Note: -Trace only works together with -Watch; it will be ignored this run.' -ForegroundColor Yellow
    $Trace = $false
}
if ($DryRun -and -not ($Fix -or $RestoreFrom)) {
    Write-Host 'Note: -DryRun only affects -Fix and -RestoreFrom. A plain report never changes anything anyway.' -ForegroundColor Yellow
}
if ($Force -and -not ($Fix -or $RestoreFrom)) {
    Write-Host 'Note: -Force only affects -Fix and -RestoreFrom; it is ignored this run.' -ForegroundColor Yellow
}

# ===========================================================================
# Elevation
# ===========================================================================
# Making changes and USB tracing need administrator rights. If we are not elevated,
# relaunch this same script (with the same parameters) in an elevated window and end
# this instance. A plain read-only report and any -DryRun preview run un-elevated,
# though with less detail (event logs and device power flags need admin).
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$NeedsAdmin = ((($Fix -or $RestoreFrom) -and -not $DryRun) -or $Trace)
if ($NeedsAdmin -and -not $IsAdmin) {
    Write-Host 'This mode needs administrator rights. Relaunching elevated (Windows will ask for permission)...' -ForegroundColor Yellow
    # Rebuild the command line from the parameters this run was given
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $argList += ('-{0}' -f $kv.Key) }
        }
        else {
            # A trailing backslash before the closing quote would escape it, so trim it
            $argList += ('-{0}' -f $kv.Key)
            $argList += ('"{0}"' -f ([string]$kv.Value).TrimEnd('\'))
        }
    }
    $exe = (Get-Process -Id $PID).Path
    try { Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs -ErrorAction Stop | Out-Null }
    catch { Write-Host "Elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red }
    exit 0
}

# ===========================================================================
# Output, logging and screen helpers
# ===========================================================================
# Every run gets a timestamp that is shared by its report, log, backup and trace, so
# the files from one run are easy to match up.
$Stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'

# Exit code for the whole run: 0 = completed, 1 = an unexpected error occurred,
# 2 = refused to run (a safety check failed). Useful when running from other tools.
$script:ExitCode = 0

# Every finding is collected here so the end of the run can summarise them and
# decide whether to suggest -Fix.
$Findings   = New-Object System.Collections.Generic.List[object]

# Remember how many errors PowerShell had recorded before we started. At the end, any
# NEW entries in $Error are non-fatal problems this run hit; they are written to the log
# so nothing goes unnoticed, even errors that were deliberately not shown on screen.
$ErrorCountAtStart = $Error.Count

# Tests whether a folder exists (creating it if needed) and can actually be written to,
# by writing and deleting a small probe file. Returns $true or $false; never throws.
function Test-FolderWritable {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $probe = Join-Path $Path ('.write-test-' + [guid]::NewGuid().ToString('N') + '.tmp')
        [System.IO.File]::WriteAllText($probe, 'write test')
        [System.IO.File]::Delete($probe)
        return $true
    }
    catch { return $false }
}

# Choose the output folder: the requested one if writable, otherwise the user's temp folder.
$OutputFolderOk = Test-FolderWritable $OutputFolder
if (-not $OutputFolderOk) {
    Write-Host "Cannot write to '$OutputFolder'; using the temp folder instead." -ForegroundColor Yellow
    $OutputFolder   = Join-Path $env:TEMP 'FiiO-K7-Diagnose'
    $OutputFolderOk = Test-FolderWritable $OutputFolder
}
$ReportPath = Join-Path $OutputFolder "FiiO-K7-Report-$Stamp.txt"
$LogPath    = Join-Path $OutputFolder "FiiO-K7-Log-$Stamp.log"
$BackupPath = Join-Path $OutputFolder "FiiO-K7-Backup-$Stamp.json"
$TracePath  = Join-Path $OutputFolder "FiiO-K7-UsbTrace-$Stamp.etl"

# The log file is enabled only if the folder is writable. If writing ever fails later
# (disk full, file locked), logging switches itself off with one warning rather than
# breaking the run.
$script:LogEnabled = $OutputFolderOk

# Writes one timestamped line to the log file. Levels:
#   DEBUG  - detail lines and commands run       INFO   - normal progress and OK/Info findings
#   WARN   - warnings and failed non-change steps ERROR  - faults and unexpected errors
#   CHANGE - a real change to the system         DRYRUN - a change that -DryRun skipped
# This function never throws: logging must never be the thing that breaks the script.
function Write-Log {
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'CHANGE', 'DRYRUN')][string]$Level = 'INFO',
        [string]$Message
    )
    if (-not $script:LogEnabled) { return }
    $line = '{0:yyyy-MM-dd HH:mm:ss.fff} [{1,-6}] {2}' -f (Get-Date), $Level, $Message
    try { [System.IO.File]::AppendAllText($LogPath, $line + [Environment]::NewLine, [System.Text.Encoding]::UTF8) }
    catch {
        $script:LogEnabled = $false
        Write-Host "  (Logging to file stopped: $($_.Exception.Message))" -ForegroundColor Yellow
    }
}

# Prints a cyan banner that starts a numbered section of the report
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Log INFO "===== $Title ====="
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
    # Map the finding level to a log level
    $logLevel = @{ OK = 'INFO'; Info = 'INFO'; Warn = 'WARN'; Fault = 'ERROR' }[$Level]
    Write-Log $logLevel "Finding [$Level/$Area] $Message$(if ($Advice) { " | Advice: $Advice" })"
}

# Prints an indented grey detail line (and logs it at DEBUG level)
function Write-Detail {
    param([string]$Text)
    Write-Host "          $Text" -ForegroundColor DarkGray
    Write-Log DEBUG $Text
}

# Prints a plain line of text in a colour (and logs it at INFO level)
function Write-Line {
    param([string]$Text, [string]$Colour = 'Gray')
    Write-Host $Text -ForegroundColor $Colour
    Write-Log INFO ($Text.Trim())
}

# Records an unexpected error in one section without stopping the whole run, so a
# problem in (say) the event log check cannot prevent the rest of the report.
function Write-SectionError {
    param([string]$Section, $ErrorRecord)
    $msg = "$($ErrorRecord.Exception.Message)"
    $where = ''
    try { $where = " (line $($ErrorRecord.InvocationInfo.ScriptLineNumber))" } catch { }
    Write-Finding Warn 'Script' "Section '$Section' hit an unexpected error and was cut short: $msg$where" `
        'The rest of the report is still valid. Please include the log file if you report this.'
    Write-Log ERROR "Section '$Section' error$where : $msg"
    try { Write-Log ERROR ("Stack: " + ($ErrorRecord.ScriptStackTrace -replace '\r?\n', ' <- ')) } catch { }
}

# Asks a Y/N question; -Force answers yes automatically, -DryRun answers yes because
# nothing will actually change. If the prompt itself fails (for example the script is
# running without a console), the answer is treated as NO: the safe default.
function Confirm-Step {
    param([string]$Question)
    if ($DryRun) { Write-Log DRYRUN "Auto-yes (dry run): $Question"; return $true }
    if ($Force)  { Write-Log INFO "Auto-yes (-Force): $Question"; return $true }
    try { $answer = Read-Host "  $Question [Y/N]" }
    catch {
        Write-Log WARN "Prompt failed, treating as No: $Question ($($_.Exception.Message))"
        return $false
    }
    $yes = ($answer -match '^\s*(y|yes)\s*$')
    Write-Log INFO "Prompt: $Question -> $(if ($yes) { 'YES' } else { "NO ('$answer')" })"
    return $yes
}

function Get-ProblemText {
    param([int]$Code)
    if ($ProblemText.ContainsKey($Code)) { return $ProblemText[$Code] }
    return "Problem code $Code"
}

# Safely reads a property from an object. Under strict mode, reading a property that
# does not exist is an error; this returns $null instead.
function Get-ObjProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# Runs an external Windows program (powercfg, pnputil, logman) and returns an object
# with Success, ExitCode and Output. Every run, its exit code and (on failure) its
# last output lines are logged. With -Change, the command is a system change: under
# -DryRun it is NOT run, only reported.
function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [switch]$Change
    )
    $cmdLine = "$FilePath $($Arguments -join ' ')"
    if ($Change -and $DryRun) {
        Write-Host "    [DRY RUN] would run: $cmdLine" -ForegroundColor Magenta
        Write-Log DRYRUN "Would run: $cmdLine"
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Output = @(); DryRun = $true }
    }
    Write-Log $(if ($Change) { 'CHANGE' } else { 'DEBUG' }) "Running: $cmdLine"
    $out  = @()
    $code = -1
    try {
        # 2>&1 merges error output into normal output so it can be logged; "$_" turns
        # each line into plain text
        $out  = @(& $FilePath @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    }
    catch {
        Write-Log ERROR "Could not run '$cmdLine': $($_.Exception.Message)"
        return [pscustomobject]@{ Success = $false; ExitCode = -1; Output = @("$($_.Exception.Message)"); DryRun = $false }
    }
    if ($null -eq $code) { $code = 0 }
    $ok = ($code -eq 0)
    if ($ok) { Write-Log DEBUG "Exit code 0 from: $FilePath" }
    else     { Write-Log WARN "Exit code $code from '$cmdLine': $((@($out) | Select-Object -Last 3) -join ' / ')" }
    return [pscustomobject]@{ Success = $ok; ExitCode = $code; Output = $out; DryRun = $false }
}

# ===========================================================================
# Device helpers
# ===========================================================================
# Device properties fetched for each K7 / Unknown USB device instance
$DevKeys = @(
    'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_Service', 'DEVPKEY_Device_DriverVersion',
    'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverDate',
    'DEVPKEY_Device_Parent', 'DEVPKEY_Device_LocationPaths', 'DEVPKEY_Device_BusReportedDeviceDesc',
    'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate', 'DEVPKEY_Device_IsPresent',
    'DEVPKEY_Device_ContainerId', 'DEVPKEY_Device_Driver'
)

# Returns a hashtable of the DEVPKEY_* properties above for one device instance.
# Properties a device does not have are simply absent.
function Get-DevProps {
    param([string]$InstanceId)
    $h = @{}
    try {
        $props = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $DevKeys -ErrorAction SilentlyContinue
        foreach ($p in @($props)) {
            # Some returned entries have no "Data" field at all (the device simply lacks
            # that property). Get-ObjProp reads them safely instead of erroring under
            # strict mode, which would otherwise lose every property after that one.
            $data = Get-ObjProp $p 'Data'
            $key  = Get-ObjProp $p 'KeyName'
            if ($key -and $null -ne $data) { $h[$key] = $data }
        }
    }
    catch { Write-Log WARN "Could not read properties of $InstanceId : $($_.Exception.Message)" }
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

# Reads a registry value as a whole number without throwing, so missing keys/values do
# not clutter the transcript. Handles both DWORD values and 4-byte binary values (the
# audio driver stores its idle settings as binary). Returns $null if absent/unreadable.
function Get-RegDword {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $v = $key.GetValue($Name, $null)
        if ($null -eq $v) { return $null }
        if ($v -is [byte[]]) {
            if ($v.Length -ge 4) { return [int64][BitConverter]::ToUInt32($v, 0) }
            return $null
        }
        return [int64]$v
    }
    catch {
        Write-Log WARN "Could not read $Path\$Name : $($_.Exception.Message)"
        return $null
    }
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
# parsing the text output of "powercfg /query". Values are null if unreadable
# (for example on non-English Windows, where powercfg's labels are translated).
function Get-PowerSetting {
    param([string]$Sub, [string]$Setting, [string]$Scheme = 'SCHEME_CURRENT')
    $result = [pscustomobject]@{ AC = $null; DC = $null }
    $r = Invoke-Native 'powercfg.exe' @('/query', $Scheme, $Sub, $Setting)
    if (-not $r.Success -or -not $r.Output) { return $result }
    $text = $r.Output -join "`n"
    $ac = [regex]::Match($text, 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)')
    $dc = [regex]::Match($text, 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)')
    if ($ac.Success) { $result.AC = [Convert]::ToInt32($ac.Groups[1].Value, 16) }
    if ($dc.Success) { $result.DC = [Convert]::ToInt32($dc.Groups[1].Value, 16) }
    return $result
}

# Name of the active power plan, e.g. "Balanced"
function Get-ActiveSchemeName {
    $r = Invoke-Native 'powercfg.exe' @('/getactivescheme')
    $m = [regex]::Match(($r.Output -join ' '), '\(([^)]+)\)\s*$')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

# GUID of the active power plan (needed so backups restore to the right plan)
function Get-ActiveSchemeGuid {
    $r = Invoke-Native 'powercfg.exe' @('/getactivescheme')
    $m = [regex]::Match(($r.Output -join ' '), '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    if ($m.Success) { return $m.Value }
    return $null
}

# Returns the WMI records behind Device Manager's "Allow the computer to turn off
# this device to save power" checkbox. Empty if not elevated.
function Get-MSPowerEntries {
    try { return @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop) }
    catch {
        Write-Log WARN "MSPower_DeviceEnable unavailable: $($_.Exception.Message)"
        return @()
    }
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

# Returns the set of instance IDs of devices connected RIGHT NOW. Used to re-check,
# immediately before removing a device entry, that the device really is disconnected.
function Get-PresentIdSet {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue)) { [void]$set.Add($d.InstanceId) }
    return , $set   # the comma stops PowerShell unrolling the set into a list
}

# ===========================================================================
# Safety functions: allow-lists, backup, restore point, single-instance lock
# ===========================================================================

# Returns $true only if a registry path + value name is on the allow-list above.
function Test-AllowedRegistryTarget {
    param([string]$Path, [string]$Name)
    foreach ($t in $AllowedRegistryTargets) {
        if ($Path -match $t.PathPattern -and $t.Names -contains $Name) { return $true }
    }
    return $false
}

# Returns $true only if a power setting (sub-group + setting GUID) is on the allow-list.
function Test-AllowedPowerSetting {
    param([string]$Sub, [string]$Setting)
    foreach ($a in $AllowedPowerSettings) {
        if ($a.Sub -eq $Sub -and $a.Setting -eq $Setting) { return $true }
    }
    return $false
}

# The backup records the ORIGINAL value of everything -Fix changes. It lives in memory
# and is written to disk BEFORE each change is made, so even if the script is
# interrupted mid-change, the backup already knows how to undo it.
$script:Backup = $null

# Writes the backup to disk safely: first to a temporary file, then swapped into place,
# so a crash can never leave a half-written backup. Returns $true on success.
function Save-Backup {
    if ($DryRun -or $null -eq $script:Backup) { return $true }
    $tmp = "$BackupPath.tmp"
    try {
        $json = $script:Backup | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.Encoding]::UTF8)
        if (Test-Path -LiteralPath $BackupPath) { [System.IO.File]::Replace($tmp, $BackupPath, $null) }
        else                                    { [System.IO.File]::Move($tmp, $BackupPath) }
        Write-Log DEBUG "Backup saved ($($script:Backup.Power.Count) power, $($script:Backup.Registry.Count) registry, $($script:Backup.MSPower.Count) device-power entries)"
        return $true
    }
    catch {
        Write-Host "    Could not write the backup file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log ERROR "Backup write failed: $($_.Exception.Message)"
        return $false
    }
}

# Creates the backup file at the start of -Fix and reads it back to prove it is valid.
# If this fails, -Fix refuses to change anything: no backup, no changes.
function Initialize-Backup {
    param([string]$SchemeGuid)
    $script:Backup = [ordered]@{
        Created       = (Get-Date).ToString('s')
        ScriptVersion = $ScriptVersion
        ComputerName  = $env:COMPUTERNAME
        SchemeGuid    = $SchemeGuid
        Power         = New-Object System.Collections.Generic.List[object]
        Registry      = New-Object System.Collections.Generic.List[object]
        MSPower       = New-Object System.Collections.Generic.List[object]
        Removed       = New-Object System.Collections.Generic.List[object]   # for the record only; see F4
    }
    if ($DryRun) { return $true }
    if (-not (Save-Backup)) { return $false }
    try {
        $check = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ((Get-ObjProp $check 'ComputerName') -ne $env:COMPUTERNAME) { throw 'read-back mismatch' }
        Write-Log INFO "Backup file created and verified: $BackupPath"
        return $true
    }
    catch {
        Write-Log ERROR "Backup verification failed: $($_.Exception.Message)"
        return $false
    }
}

# Creates a Windows System Restore point the first time it is called (before the first
# real change), so even changes outside this script's own backup can be rolled back.
# Windows may silently skip creating one (System Restore off, or one was made in the
# last 24 hours), so this compares the restore point list before and after.
$script:RestorePointState = 'NotAttempted'   # NotAttempted / Created / Skipped / Failed / Declined
function Confirm-RestorePoint {
    if ($DryRun -or $NoRestorePoint) { return $true }
    if ($script:RestorePointState -ne 'NotAttempted') { return ($script:RestorePointState -ne 'Declined') }

    Write-Host '    Creating a System Restore point first (this can take a minute)...' -ForegroundColor Gray
    Write-Log INFO 'Creating System Restore point'
    $before = @()
    try { $before = @(Get-CimInstance -Namespace 'root/default' -ClassName 'SystemRestore' -ErrorAction Stop) } catch { }
    $ok = $false
    $reason = ''
    try {
        $r = Invoke-CimMethod -Namespace 'root/default' -ClassName 'SystemRestore' -MethodName 'CreateRestorePoint' -ErrorAction Stop -Arguments @{
            Description      = "Before FiiO K7 fixes ($Stamp)"
            RestorePointType = [uint32]12    # 12 = MODIFY_SETTINGS
            EventType        = [uint32]100   # 100 = BEGIN_SYSTEM_CHANGE
        }
        if ($r.ReturnValue -eq 0) {
            $after = @()
            try { $after = @(Get-CimInstance -Namespace 'root/default' -ClassName 'SystemRestore' -ErrorAction Stop) } catch { }
            if ($after.Count -gt $before.Count) { $ok = $true }
            else { $reason = 'Windows skipped it (System Restore may be off for drive C:, or a restore point was made in the last 24 hours).' }
        }
        else { $reason = "Windows returned error code $($r.ReturnValue) (System Restore may be turned off)." }
    }
    catch { $reason = $_.Exception.Message }

    if ($ok) {
        $script:RestorePointState = 'Created'
        Write-Host '    Restore point created.' -ForegroundColor Green
        Write-Log CHANGE 'System Restore point created'
        return $true
    }
    Write-Host "    No restore point was created: $reason" -ForegroundColor Yellow
    Write-Log WARN "Restore point not created: $reason"
    Write-Host '    The backup file still lets -RestoreFrom undo every setting this script changes.' -ForegroundColor Yellow
    if (Confirm-Step 'Continue without a restore point?') {
        $script:RestorePointState = 'Skipped'
        return $true
    }
    $script:RestorePointState = 'Declined'
    return $false
}

# Single-instance lock: a system-wide "mutex" (a named lock) stops two copies of this
# script changing settings at the same time and overwriting each other's backups.
$script:Mutex = $null
function Enter-ChangeLock {
    try {
        $script:Mutex = New-Object System.Threading.Mutex($false, 'Global\FiiO-K7-Diagnose')
        $got = $false
        try { $got = $script:Mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $got = $true }   # a previous run crashed; the lock is ours now
        if (-not $got) { $script:Mutex.Dispose(); $script:Mutex = $null }
        return $got
    }
    catch {
        Write-Log WARN "Could not create the single-instance lock: $($_.Exception.Message)"
        return $true   # the lock is a convenience; failing to create it is not a reason to stop
    }
}
function Exit-ChangeLock {
    if ($script:Mutex) {
        try { $script:Mutex.ReleaseMutex() } catch { }
        try { $script:Mutex.Dispose() } catch { }
        $script:Mutex = $null
    }
}

# ===========================================================================
# USB trace (ETW) functions, used by -Watch -Trace
# ===========================================================================
# Tracks whether our trace session is running, so the clean-up code can always stop it.
$script:EtwRunning = $false

# Stops our ETW session if it exists. Safe to call at any time, any number of times.
function Stop-UsbTrace {
    $q = Invoke-Native 'logman.exe' @('query', $EtwSessionName, '-ets')
    if ($q.Success) {
        $s = Invoke-Native 'logman.exe' @('stop', $EtwSessionName, '-ets')
        if ($s.Success) { Write-Log INFO "USB trace session '$EtwSessionName' stopped" }
        else            { Write-Log ERROR "Could not stop USB trace session '$EtwSessionName' (exit $($s.ExitCode)). Stop it manually: logman stop $EtwSessionName -ets" }
    }
    $script:EtwRunning = $false
}

# Starts the USB trace. Returns $true if at least the first provider started.
function Start-UsbTrace {
    # A session with our name may be left over from an interrupted run: stop it first
    Stop-UsbTrace
    $first = $EtwProviders[0]
    $r = Invoke-Native 'logman.exe' @('start', $EtwSessionName, '-ets', '-p', $first, 'Default', '-o', $TracePath, '-max', "$EtwMaxFileMB")
    if (-not $r.Success) {
        Write-Log ERROR "USB trace failed to start: $((@($r.Output) | Select-Object -Last 2) -join ' / ')"
        return $false
    }
    $script:EtwRunning = $true
    foreach ($p in ($EtwProviders | Select-Object -Skip 1)) {
        $u = Invoke-Native 'logman.exe' @('update', $EtwSessionName, '-ets', '-p', $p, 'Default')
        if (-not $u.Success) { Write-Detail "Could not add trace provider $p (exit $($u.ExitCode)); continuing without it." }
    }
    return $true
}

# Reads the trace file and picks out events that suggest a problem. A healthy USB
# trace contains hundreds of routine events, so this uses a heuristic: an event is
# "suspicious" if it is logged as warning/error, its task or message mentions a
# failure, or it carries an NTSTATUS error code (a value of 0xC0000000 or above).
# It is a pointer for a human, not a verdict; the raw .etl file is kept for experts.
function Get-UsbTraceAnalysis {
    $result = [pscustomobject]@{ Total = 0; ByProvider = @(); Suspicious = @() }
    if (-not (Test-Path -LiteralPath $TracePath)) { return $result }
    $events = @()
    try { $events = @(Get-WinEvent -Path $TracePath -Oldest -MaxEvents 200000 -ErrorAction Stop) }
    catch {
        Write-Log WARN "Could not read the USB trace file: $($_.Exception.Message)"
        return $result
    }
    $result.Total = $events.Count
    # Count events per provider. The one event with no provider name is the trace file's
    # own header record, written by Windows when the trace starts.
    $result.ByProvider = @($events | Group-Object ProviderName | ForEach-Object {
        $pn = if ($_.Name) { $_.Name } else { '(trace file header)' }
        "${pn}: $($_.Count)"
    })
    $sus = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        $reasons = @()
        if ($e.Level -ge 1 -and $e.Level -le 3) { $reasons += 'warning/error level' }
        $label = ''
        try { $label = "$($e.TaskDisplayName) $($e.OpcodeDisplayName)" } catch { }
        if ($label -match 'fail|error|reset|timeout|time out|abort|stall') { $reasons += 'failure task' }
        $msg = ''
        try { $msg = [string]$e.Message } catch { }
        if ($msg -match 'fail|error|timed out|timeout') { $reasons += 'failure message' }
        try {
            # Event fields can sit under <EventData> or <UserData>, with or without a
            # "Name" attribute. This XPath query finds every element, wherever it is,
            # whose name (or Name attribute) mentions "Status", without relying on a
            # fixed layout (which would error under strict mode when it differs).
            $x = [xml]$e.ToXml()
            $nodes = $x.SelectNodes("//*[contains(local-name(), 'Status') or contains(@Name, 'Status')]")
            foreach ($d in @($nodes)) {
                if ($null -eq $d) { continue }
                $fieldName = $d.LocalName
                $nameAttr = $d.GetAttribute('Name')
                if ($nameAttr) { $fieldName = $nameAttr }
                $raw = "$($d.InnerText)".Trim()
                $num = $null
                if ($raw -match '^0x([0-9a-fA-F]{1,16})$') { $num = [Convert]::ToInt64($Matches[1], 16) }
                elseif ($raw -match '^-?\d{1,19}$')       { $num = [int64]$raw; if ($num -lt 0) { $num = $num + 4294967296L } }
                # NTSTATUS error codes are 0xC0000000 and above. The "L" suffix matters:
                # without it PowerShell reads 0xC0000000 as a NEGATIVE 32-bit number, and
                # every value (even 0 = success) would wrongly count as an error.
                if ($null -ne $num -and $num -ge 0xC0000000L -and $num -le 4294967295L) { $reasons += ('{0}=0x{1:X8}' -f $fieldName, $num) }
            }
        }
        catch { }
        if ($reasons.Count -gt 0) {
            $sus.Add([pscustomobject]@{ Time = $e.TimeCreated; Provider = $e.ProviderName; Id = $e.Id; Task = $label.Trim(); Why = ($reasons -join ', '); Message = (Get-ShortMessage $msg 140) })
        }
    }
    # .ToArray() turns the list into a plain array. (Wrapping the list in @(...) fails
    # with "Argument types do not match" when the list is empty.)
    $result.Suspicious = $sus.ToArray()
    return $result
}

# ===========================================================================
# Clean-up: always runs at the end (see the "finally" block at the bottom)
# ===========================================================================
# Undoes anything temporary this run set up: the USB trace, WMI event subscriptions,
# the single-instance lock and the transcript. Each step is protected so one failing
# step cannot stop the others.
$script:TranscriptOn = $false
$CaptureSourceIds = @('K7W_Create', 'K7W_Delete', 'K7W_Modify')
function Invoke-Cleanup {
    if ($script:EtwRunning) { try { Stop-UsbTrace } catch { } }
    # -ErrorAction Ignore: "no such subscription" is the normal case when -Watch was not used
    foreach ($s in $CaptureSourceIds) { try { Unregister-Event -SourceIdentifier $s -ErrorAction Ignore } catch { } }
    try { Exit-ChangeLock } catch { }

    # Write every non-fatal error PowerShell recorded during this run to the log, so the
    # log is a complete record. ($Error holds the newest error first.)
    try {
        $newErrors = $Error.Count - $ErrorCountAtStart
        if ($newErrors -gt 0) {
            Write-Log INFO "Non-fatal errors recorded during this run: $newErrors (details follow)"
            for ($i = [math]::Min($newErrors, $Error.Count) - 1; $i -ge 0; $i--) {
                $er = $Error[$i]
                $line = ''
                try { $line = " (line $($er.InvocationInfo.ScriptLineNumber))" } catch { }
                Write-Log DEBUG ("  Error$line : " + (Get-ShortMessage "$er" 300))
            }
        }
    }
    catch { }

    Write-Log INFO "Run finished with exit code $($script:ExitCode)"
    if ($script:TranscriptOn) {
        try { Stop-Transcript | Out-Null } catch { }
        $script:TranscriptOn = $false
    }
}

# ###########################################################################
# MAIN BODY
# Everything below runs inside try { } finally { }. Whatever happens - success, an
# unexpected error, or the user pressing Ctrl+C - the "finally" block still runs and
# cleans up (stops the USB trace, releases the lock, closes the transcript).
# ###########################################################################
try {
    # A "trap" catches any unexpected terminating error that is not already handled,
    # logs it with its line number, and continues with the next statement, so one
    # failure never silently ends the run.
    trap {
        $script:ExitCode = 1
        $line = ''
        try { $line = " (line $($_.InvocationInfo.ScriptLineNumber))" } catch { }
        Write-Host "  Unexpected error$line : $($_.Exception.Message)" -ForegroundColor Red
        Write-Log ERROR "Unexpected error$line : $($_.Exception.Message)"
        continue
    }

    # Start the transcript (an exact copy of the screen output). If this fails the run
    # continues; the log file still records everything important.
    try {
        Start-Transcript -LiteralPath $ReportPath -Force -ErrorAction Stop | Out-Null
        $script:TranscriptOn = $true
    }
    catch { Write-Host "  Could not start the transcript: $($_.Exception.Message)" -ForegroundColor Yellow }

    Write-Log INFO "FiiO K7 diagnostics v$ScriptVersion started. Parameters: $(($PSBoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' ')"
    Write-Log INFO "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), admin=$IsAdmin, user=$env:USERNAME, computer=$env:COMPUTERNAME"

    Write-Line "FiiO K7 USB recognition diagnostics v$ScriptVersion - $(Get-Date -Format 'dddd d MMMM yyyy HH:mm:ss')" 'White'
    Write-Line "Report: $ReportPath"
    Write-Line "Log:    $LogPath"
    if ($DryRun -and ($Fix -or $RestoreFrom)) {
        Write-Line 'DRY RUN: nothing will be changed. Lines marked [DRY RUN] show what would happen.' 'Magenta'
    }
    if (-not $IsAdmin) {
        Write-Line 'Not running as administrator: some event logs and device power settings will be missing.' 'Yellow'
        Write-Line 'Re-run from an elevated PowerShell for the full picture.' 'Yellow'
    }

    # =======================================================================
    # 0. Pre-flight safety checks
    # =======================================================================
    # Before reading anything in depth (and long before changing anything), confirm the
    # environment is one this script was written for. "Blocking" problems stop -Fix and
    # -RestoreFrom from making changes; the read-only report still runs where it can.
    Write-Section '0. Pre-flight safety checks'
    $ChangesBlocked = $false            # set to $true if any check makes changes unsafe
    $FreeMB = $null
    try {
        # Windows only: everything below uses Windows-only tools
        if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
            Write-Finding Fault 'Pre-flight' 'This is not Windows. The script cannot run here.'
            $script:ExitCode = 2
            return
        }
        $cvPre = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $BuildPre = 0
        [void][int]::TryParse([string](Get-ObjProp $cvPre 'CurrentBuildNumber'), [ref]$BuildPre)
        Write-Detail "Windows build: $BuildPre"
        if ($BuildPre -lt 19041) {
            Write-Finding Warn 'Pre-flight' "Windows build $BuildPre is older than Windows 10 2004 (19041), which this script was written for." `
                'The report still runs, but fixes are disabled because some tools (e.g. pnputil /remove-device) are missing.'
            $ChangesBlocked = $true
        }

        # 32-bit PowerShell on 64-bit Windows sees a redirected copy of parts of the
        # registry and different system tools: unsafe for changes.
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            Write-Finding Fault 'Pre-flight' 'This is 32-bit PowerShell on 64-bit Windows.' `
                'It sees a redirected view of the registry, so fixes are disabled. Run the normal (64-bit) PowerShell instead.'
            $ChangesBlocked = $true
        }
        Write-Detail "PowerShell: $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition), $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' })"
        Write-Detail "Administrator: $IsAdmin"

        # The output folder must be writable: without it there is no backup, so no changes
        if (-not $OutputFolderOk) {
            Write-Finding Fault 'Pre-flight' 'No writable folder for reports and backups was found.' `
                'Fixes are disabled, because changes are never made without a backup. Use -OutputFolder to choose a writable folder.'
            $ChangesBlocked = $true
        }
        else { Write-Detail "Output folder: $OutputFolder (writable)" }

        # Free space on the output drive (traces can be large)
        try {
            $root = [System.IO.Path]::GetPathRoot($OutputFolder)
            $drive = New-Object System.IO.DriveInfo($root)
            $FreeMB = [math]::Round($drive.AvailableFreeSpace / 1MB)
            Write-Detail "Free space on $root : $FreeMB MB"
        }
        catch { Write-Log WARN "Could not read free disk space: $($_.Exception.Message)" }

        # Required Windows tools must exist
        foreach ($tool in 'powercfg.exe', 'pnputil.exe', 'logman.exe') {
            if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
                Write-Finding Warn 'Pre-flight' "Windows tool $tool was not found." 'Parts of the report and the fixes that depend on it are skipped.'
                if ($tool -ne 'logman.exe') { $ChangesBlocked = $true }
            }
        }

        # A pending restart means Windows is half-way through installing something.
        # Changing device settings on top of that muddies the results.
        $pending = @()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'Windows component servicing' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'Windows Update' }
        $RestartPending = ($pending.Count -gt 0)
        if ($RestartPending) {
            Write-Finding Warn 'Pre-flight' "A restart is pending ($($pending -join ', '))." `
                'Restart Windows first, then run this again: an unfinished update can itself cause the K7 problem, and makes results harder to read.'
        }
        else { Write-Finding OK 'Pre-flight' 'No restart is pending.' }

        # Single-instance lock for runs that change things
        if (($Fix -or $RestoreFrom) -and -not $DryRun) {
            if (-not (Enter-ChangeLock)) {
                Write-Finding Fault 'Pre-flight' 'Another copy of this script is already making changes.' 'Wait for it to finish, then run this again.'
                $ChangesBlocked = $true
            }
        }

        if ($ChangesBlocked -and ($Fix -or $RestoreFrom)) {
            Write-Line '  Changes are DISABLED for this run because of the problem(s) above. The report will still run.' 'Red'
            $script:ExitCode = 2
        }
        elseif (-not $ChangesBlocked) {
            Write-Finding OK 'Pre-flight' 'Environment checks passed.'
        }
    }
    catch { Write-SectionError '0. Pre-flight' $_ }

    # =======================================================================
    # Restore mode
    # =======================================================================
    # Reads a backup JSON written by -Fix and puts back the original values:
    # power-plan settings, registry values (deleting any that did not exist before)
    # and the per-device "allow turn off" flags. Then ends without running diagnostics.
    # Every entry in the file is checked against the safety allow-lists first, so an
    # edited or damaged backup file cannot be used to change anything else.
    if ($RestoreFrom) {
        Write-Section 'Restoring settings from backup'
        if ($ChangesBlocked) {
            Write-Line '  Restore cancelled: pre-flight checks failed (see above).' 'Red'
            return
        }

        # --- Load and validate the backup file -----------------------------------
        if (-not (Test-Path -LiteralPath $RestoreFrom -PathType Leaf)) {
            Write-Line "  Backup file not found: $RestoreFrom" 'Red'
            $script:ExitCode = 2
            return
        }
        $size = (Get-Item -LiteralPath $RestoreFrom).Length
        if ($size -gt 1MB) {
            Write-Line "  Refusing to read '$RestoreFrom': at $size bytes it is far too large to be a backup from this script." 'Red'
            $script:ExitCode = 2
            return
        }
        $b = $null
        try { $b = Get-Content -LiteralPath $RestoreFrom -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
        catch {
            Write-Line "  The backup file is not valid JSON: $($_.Exception.Message)" 'Red'
            $script:ExitCode = 2
            return
        }
        foreach ($required in 'Created', 'Power', 'Registry', 'MSPower') {
            if ($null -eq $b.PSObject.Properties[$required]) {
                Write-Line "  The file does not look like a backup from this script (missing '$required')." 'Red'
                $script:ExitCode = 2
                return
            }
        }
        Write-Detail "Backup created: $(Get-ObjProp $b 'Created') by script version $(Get-ObjProp $b 'ScriptVersion') on $(Get-ObjProp $b 'ComputerName')"

        # A backup from another PC refers to that PC's devices and power plan
        $bComputer = Get-ObjProp $b 'ComputerName'
        if ($bComputer -and $bComputer -ne $env:COMPUTERNAME) {
            Write-Line "  WARNING: this backup was made on '$bComputer', not this PC ('$env:COMPUTERNAME')." 'Yellow'
            if (-not (Confirm-Step 'Restore it anyway?')) { Write-Line '  Restore cancelled.' 'Yellow'; return }
        }

        # Work out which power plan to restore into. It must be a well-formed GUID that
        # still exists on this PC; otherwise fall back to the current plan.
        $scheme = 'SCHEME_CURRENT'
        $bScheme = [string](Get-ObjProp $b 'SchemeGuid')
        if ($bScheme -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            if ((Invoke-Native 'powercfg.exe' @('/query', $bScheme)).Success) { $scheme = $bScheme }
            else { Write-Detail "Power plan $bScheme no longer exists; restoring into the current plan instead." }
        }

        # Build the list of actions, refusing anything not on the allow-lists
        $plan = New-Object System.Collections.Generic.List[object]
        foreach ($p in @($b.Power)) {
            if ($null -eq $p) { continue }
            $sub = [string](Get-ObjProp $p 'Sub'); $set = [string](Get-ObjProp $p 'Setting')
            if (-not (Test-AllowedPowerSetting $sub $set)) { Write-Line "  REFUSED (not an allowed setting): power $sub/$set" 'Red'; Write-Log ERROR "Restore refused power $sub/$set"; continue }
            foreach ($side in 'AC', 'DC') {
                $val = Get-ObjProp $p $side
                if ($null -eq $val) { continue }
                if (-not ("$val" -match '^\d+$') -or [int]$val -gt 5) { Write-Line "  REFUSED (implausible value '$val'): power $(Get-ObjProp $p 'Name') $side" 'Red'; continue }
                $plan.Add([pscustomobject]@{ Kind = 'Power'; Name = (Get-ObjProp $p 'Name'); Sub = $sub; Setting = $set; Side = $side; Value = [int]$val })
            }
        }
        foreach ($r in @($b.Registry)) {
            if ($null -eq $r) { continue }
            $path = [string](Get-ObjProp $r 'Path'); $name = [string](Get-ObjProp $r 'Name')
            if (-not (Test-AllowedRegistryTarget $path $name)) { Write-Line "  REFUSED (not an allowed registry value): $path\$name" 'Red'; Write-Log ERROR "Restore refused registry $path\$name"; continue }
            $existed = [bool](Get-ObjProp $r 'Existed')
            $val = Get-ObjProp $r 'Value'
            if ($existed -and -not ("$val" -match '^\d+$')) { Write-Line "  REFUSED (implausible value '$val'): $path\$name" 'Red'; continue }
            $plan.Add([pscustomobject]@{ Kind = 'Registry'; Path = $path; Name = $name; Existed = $existed; Value = $val })
        }
        foreach ($m in @($b.MSPower)) {
            if ($null -eq $m) { continue }
            $inst = [string](Get-ObjProp $m 'InstanceName')
            if ($inst -notmatch '^USB\\') { Write-Line "  REFUSED (not a USB device): power management for $inst" 'Red'; Write-Log ERROR "Restore refused MSPower $inst"; continue }
            $plan.Add([pscustomobject]@{ Kind = 'MSPower'; InstanceName = $inst; Enable = [bool](Get-ObjProp $m 'Enable') })
        }

        if ($plan.Count -eq 0) {
            Write-Line '  The backup contains nothing to restore.' 'Yellow'
            return
        }

        # Show the plan and confirm before touching anything
        Write-Line "  The following $($plan.Count) change(s) will be made:" 'White'
        foreach ($a in $plan) {
            switch ($a.Kind) {
                'Power'    { Write-Detail "Power plan: $($a.Name) $($a.Side) -> $($a.Value)" }
                'Registry' { Write-Detail "Registry  : $($a.Path)\$($a.Name) -> $(if ($a.Existed) { $a.Value } else { '(delete: did not exist before)' })" }
                'MSPower'  { Write-Detail "Device    : 'allow turn off' -> $($a.Enable) for $($a.InstanceName)" }
            }
        }
        if (-not (Confirm-Step 'Go ahead with the restore?')) { Write-Line '  Restore cancelled; nothing was changed.' 'Yellow'; return }
        if (-not (Confirm-RestorePoint)) { Write-Line '  Restore cancelled; nothing was changed.' 'Yellow'; return }

        # --- Apply ------------------------------------------------------------------
        $okCount = 0; $failCount = 0
        $powerTouched = $false
        $entries = @(Get-MSPowerEntries)
        foreach ($a in $plan) {
            try {
                switch ($a.Kind) {
                    'Power' {
                        $verb = if ($a.Side -eq 'AC') { '/setacvalueindex' } else { '/setdcvalueindex' }
                        $res = Invoke-Native 'powercfg.exe' @($verb, $scheme, $a.Sub, $a.Setting, "$($a.Value)") -Change
                        if (-not $res.Success) { throw "powercfg exit code $($res.ExitCode)" }
                        $powerTouched = $true
                        if (-not $DryRun) {
                            Write-Log CHANGE "Restored power setting $($a.Name) $($a.Side) = $($a.Value)"
                            Write-Line "  Restored power setting $($a.Name) $($a.Side) = $($a.Value)"
                        }
                    }
                    'Registry' {
                        if ($DryRun) {
                            Write-Host "    [DRY RUN] would $(if ($a.Existed) { "set $($a.Path)\$($a.Name) = $($a.Value)" } else { "delete $($a.Path)\$($a.Name)" })" -ForegroundColor Magenta
                            Write-Log DRYRUN "Registry restore $($a.Path)\$($a.Name)"
                        }
                        elseif (-not (Test-Path -LiteralPath $a.Path)) {
                            # The device entry was removed since the backup; nothing to restore
                            Write-Line "  Skipped $($a.Path)\$($a.Name): the key no longer exists." 'Yellow'
                        }
                        elseif ($a.Existed) {
                            New-ItemProperty -LiteralPath $a.Path -Name $a.Name -Value ([int]$a.Value) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                            if ((Get-RegDword $a.Path $a.Name) -ne [int64]$a.Value) { throw 'value did not read back correctly' }
                            Write-Log CHANGE "Restored $($a.Path)\$($a.Name) = $($a.Value)"
                            Write-Line "  Restored $($a.Path)\$($a.Name) = $($a.Value)"
                        }
                        else {
                            if ($null -ne (Get-RegDword $a.Path $a.Name)) {
                                Remove-ItemProperty -LiteralPath $a.Path -Name $a.Name -ErrorAction Stop
                            }
                            Write-Log CHANGE "Removed $($a.Path)\$($a.Name)"
                            Write-Line "  Removed $($a.Path)\$($a.Name) (it did not exist before)"
                        }
                    }
                    'MSPower' {
                        $o = $entries | Where-Object { $_.InstanceName -eq $a.InstanceName } | Select-Object -First 1
                        if (-not $o) { Write-Line "  Skipped $($a.InstanceName): device not present now." 'Yellow'; break }
                        if ($DryRun) {
                            Write-Host "    [DRY RUN] would set 'allow turn off' = $($a.Enable) for $($a.InstanceName)" -ForegroundColor Magenta
                            Write-Log DRYRUN "MSPower restore $($a.InstanceName)"
                            break
                        }
                        Set-CimInstance -InputObject $o -Property @{ Enable = $a.Enable } -ErrorAction Stop
                        Write-Log CHANGE "Restored 'allow turn off' = $($a.Enable) for $($a.InstanceName)"
                        Write-Line "  Restored 'allow turn off' = $($a.Enable) for $($a.InstanceName)"
                    }
                }
                $okCount++
            }
            catch {
                $failCount++
                Write-Line "  Could not restore $($a.Kind) entry: $($_.Exception.Message)" 'Yellow'
                Write-Log ERROR "Restore failed for $($a.Kind): $($_.Exception.Message)"
            }
        }
        if ($powerTouched) { [void](Invoke-Native 'powercfg.exe' @('/setactive', $scheme) -Change) }

        Write-Line ''
        if ($DryRun) { Write-Line "  DRY RUN complete: $okCount item(s) would be restored. Nothing was changed." 'Magenta' }
        elseif ($failCount -eq 0) { Write-Line "  Restore complete ($okCount item(s)). Restart Windows for every change to take effect." 'Green' }
        else {
            Write-Line "  Restore finished with $failCount problem(s) out of $($plan.Count). See the log: $LogPath" 'Yellow'
            $script:ExitCode = 1
        }
        return
    }

    # Cache device lists once: enumerating devices is slow, so every section below
    # reuses these. $AllDevices includes phantom (disconnected) devices; $PresentIds
    # is the set of instance IDs that are connected right now.
    Write-Line ''
    Write-Line 'Enumerating devices (this can take a few seconds)...' 'DarkGray'
    $AllDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue)
    $PresentIds = Get-PresentIdSet
    Write-Log INFO "Devices known to Windows: $($AllDevices.Count), present now: $($PresentIds.Count)"
    if ($AllDevices.Count -eq 0) {
        Write-Finding Fault 'Script' 'Windows returned no devices at all, so the device checks below cannot work.' `
            'This usually means the PnpDevice module is unavailable. Try running from Windows PowerShell 5.1.'
    }

    # Variables that later sections depend on. They are given safe defaults here so
    # that, if an earlier section fails part-way, the later ones still work.
    $Build = 0; $AffectedBuild = $false
    $K7All = @(); $K7Roots = @(); $K7RootsPresent = @(); $K7Phantoms = @()
    $K7Mode = $null; $K7PresentOK = $false; $K7PresentError = $null; $K7ChainForFix = @()
    $Unknown = @(); $UnknownPresent = @()
    $UsbControllers = @(); $ExternalHub = $false
    $SchemeGuid = $null; $ss = [pscustomobject]@{ AC = $null; DC = $null }; $ls = [pscustomobject]@{ AC = $null; DC = $null }
    $UsbSelectiveSuspendOn = $false; $LspmOn = $false; $FastStartupOn = $false
    $MSPower = @(); $TurnOffAllowed = @()
    $K7StartFailures = @(); $UnknownEvents = @(); $EventLogBlind = $false
    $FiioPackages = @()

    # =======================================================================
    # 1. System
    # =======================================================================
    # Establish the Windows build, any Insider channel, motherboard/BIOS and recent
    # updates, so the report can be matched against Microsoft's known USB audio issue.
    Write-Section '1. Windows and hardware'
    try {
        $cv      = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        [void][int]::TryParse([string](Get-ObjProp $cv 'CurrentBuildNumber'), [ref]$Build)
        $Ubr     = Get-ObjProp $cv 'UBR'
        $Display = Get-ObjProp $cv 'DisplayVersion'
        $branch  = $null
        $selfHost = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability' -ErrorAction SilentlyContinue
        $branch = Get-ObjProp $selfHost 'BranchName'
        $board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        $bios  = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

        $osName = [string](Get-ObjProp $cv 'ProductName')
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
        foreach ($kb in $foundKBs) { Write-Detail "Installed: $kb - $($KnownIssueKBs[$kb])" }
        Write-Detail ('Latest updates: ' + (($hotfixes | Select-Object -First 5 | ForEach-Object { "$($_.HotFixID) ($(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '?' }))" }) -join ', '))
    }
    catch { Write-SectionError '1. Windows and hardware' $_ }

    # =======================================================================
    # 2. K7 devices
    # =======================================================================
    # Find every device node belonging to the K7 (present or phantom), show its driver
    # and health, and work out which USB Audio Class driver it is running on:
    #   UAC1 = usbaudio.sys (Microsoft, affected by the known issue)
    #   UAC2 = usbaudio2.sys (Microsoft)
    #   Vendor = FiiO's own Thesycon-based driver
    Write-Section '2. FiiO K7 device instances'
    try {
        $K7All = @($AllDevices | Where-Object { $_.InstanceId -match $K7IdPattern -or ($_.FriendlyName -and $_.FriendlyName -match $K7NamePattern) })
        $K7Roots = @($K7All | Where-Object { $_.InstanceId -match $K7RootPattern })
        $K7RootsPresent = @($K7Roots | Where-Object { $PresentIds.Contains($_.InstanceId) })
        $K7Phantoms = @($K7All | Where-Object { -not $PresentIds.Contains($_.InstanceId) })

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

                Write-Line ''
                Write-Line ("  {0}  [{1}]" -f $d.FriendlyName, $state) 'White'
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

            Write-Line ''
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
                'If you see Code 10 on the K7, this known issue is the likely cause. Installing the FiiO USB DAC driver moves the K7 off usbaudio.sys (install it BEFORE connecting the K7).'
        }
        elseif ($AffectedBuild -and $K7Mode) {
            Write-Finding OK 'Windows' "Microsoft's open USB audio Code 10 issue only affects USB Audio Class 1.0; the K7 is not using that driver."
        }
    }
    catch { Write-SectionError '2. FiiO K7 device instances' $_ }

    # =======================================================================
    # 3. Failed enumerations
    # =======================================================================
    # When a USB device attaches but fails to describe itself, Windows keeps an
    # "Unknown USB Device" entry (VID_0000). Finding these means the problem is at
    # the USB link level rather than a driver failure.
    Write-Section '3. Failed USB enumerations ("Unknown USB Device")'
    try {
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
                Write-Line ("  {0}  [{1}]" -f $u.FriendlyName, $state) 'White'
                Write-Detail "Instance: $($u.InstanceId)"
                if ($loc) { Write-Detail "Port    : $(@($loc)[0])" }
                if ($arr) { Write-Detail "Last seen arriving: $arr" }
            }
            Write-Finding Warn 'USB' "Windows has recorded $($Unknown.Count) failed USB enumeration(s) ($($UnknownPresent.Count) present now)." `
                'A device connected but did not answer the descriptor request. If the timing matches a K7 switch-on, the K7 attached before its USB receiver was ready, or the cable/port/hub dropped the link.'
        }
    }
    catch { Write-SectionError '3. Failed USB enumerations' $_ }

    # =======================================================================
    # 4. USB path
    # =======================================================================
    # Trace the K7 up through its hubs to the host controller. A hub that is a separate
    # device (front panel, dock, monitor) is a common cause of flaky enumeration; a hub
    # built into the motherboard is normal. Built-in devices carry a special container ID.
    Write-Section '4. USB path from the K7 to the controller'
    try {
        $UsbControllers = @($AllDevices | Where-Object { $PresentIds.Contains($_.InstanceId) -and $_.Class -eq 'USB' -and $_.FriendlyName -match 'Host Controller|xHCI|eXtensible' })
        foreach ($c in $UsbControllers) {
            $vendor = 'Other'
            if ($c.InstanceId -match 'VEN_8086') { $vendor = 'Intel' }
            elseif ($c.InstanceId -match 'VEN_1B21') { $vendor = 'ASMedia' }
            elseif ($c.InstanceId -match 'VEN_1022') { $vendor = 'AMD' }
            Write-Detail "Controller: $($c.FriendlyName) [$vendor] $($c.InstanceId)"
        }

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
            Write-Line "  $($root.FriendlyName)" 'White'
            $MachineContainer = '00000000-0000-0000-ffff-ffffffffffff'   # container ID Windows gives non-removable, built-in devices
            $ExternalHubs = @()
            $BuiltInHubs  = @()
            foreach ($link in $chain) {
                $indent += '  '
                Write-Line "$indent<- $($link.Name)  ($($link.InstanceId))"
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

            # Which controller is the K7 on? Useful for the "try another root hub" advice.
            $k7Controller = @($chain | Where-Object { $_.InstanceId -like 'PCI\*' } | Select-Object -First 1)
            $otherControllers = @($UsbControllers | Where-Object { $k7Controller.Count -eq 0 -or $_.InstanceId -ne $k7Controller[0].InstanceId })

            if ($ExternalHub) {
                Write-Finding Warn 'USB' 'The K7 connects through a USB hub that is a separate device (front panel, monitor, dock or standalone hub).' `
                    'FiiO advises a rear motherboard port; move the K7 and re-run until the path shows "USB Root Hub" or only a built-in hub above the K7.'
            }
            elseif ($BuiltInHubs.Count -gt 0) {
                Write-Finding Info 'USB' 'The K7 sits behind a hub built into the PC (typical of the motherboard rear I/O panel).' `
                    'Normal and not a fault in itself. But a built-in hub can fail to enumerate a device too: if the K7 keeps failing, try a rear port that is wired straight to a root hub (or to a different controller).'
            }
            else {
                Write-Finding OK 'USB' 'The K7 connects directly to a motherboard root hub port (no intermediate hub detected).'
            }
            if ($otherControllers.Count -gt 0) {
                Write-Detail "This PC has $($otherControllers.Count) other USB controller(s). Ports on a different controller use a completely separate USB path - a good test if the K7 fails."
            }
        }
        else {
            Write-Detail 'The K7 is not connected, so its USB path cannot be traced. Run again with the K7 working to see it.'
        }
    }
    catch { Write-SectionError '4. USB path' $_ }

    # =======================================================================
    # 5. Power management
    # =======================================================================
    # Windows power saving can suspend USB ports or hubs and leave a device that
    # attaches at the wrong moment unanswered. Check the power plan, Fast Startup and
    # the per-device "turn off to save power" flags on the K7's path.
    Write-Section '5. Power management'
    try {
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

        foreach ($r in $K7Roots) {
            $dp = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($r.InstanceId)\Device Parameters"
            foreach ($n in 'EnhancedPowerManagementEnabled', 'SelectiveSuspendEnabled', 'AllowIdleIrpInD3') {
                $v = Get-RegDword $dp $n
                if ($null -ne $v) { Write-Detail "$($r.InstanceId): $n = $v" }
            }
        }
    }
    catch { Write-SectionError '5. Power management' $_ }

    # =======================================================================
    # 6. Event logs
    # =======================================================================
    # Search the Kernel-PnP and System logs for the K7 or Unknown USB Devices.
    # Event 411 = a device driver failed to start. Event 400/410 = device configured/started.
    # If the K7 clearly arrived but no events exist, the log is "blind" (not elevated or
    # disabled), and the absence of failures cannot be trusted.
    Write-Section "6. Event logs (last $Days days)"
    try {
        $Since = (Get-Date).AddDays(-$Days)
        $PnpAll = @()
        try {
            $PnpAll = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; StartTime = $Since } -ErrorAction Stop)
        }
        catch {
            # "No events were found" is a normal answer, not a failure
            if ($_.Exception.Message -notmatch 'No events were found') { Write-Detail "Kernel-PnP/Configuration log unavailable: $($_.Exception.Message)" }
        }
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
        $EventLogBlind = [bool]($K7Arrival -and $K7Arrival -gt $Since -and $K7Configured.Count -eq 0)
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
        # -ErrorAction Ignore (not SilentlyContinue): a missing provider is an expected
        # answer here, so it should not be recorded as an error in the log either.
        $sysProviders = @($wantedProviders | Where-Object { Get-WinEvent -ListProvider $_ -ErrorAction Ignore })
        Write-Log DEBUG "System log providers available: $($sysProviders -join ', ')"
        if ($sysProviders.Count -gt 0) {
            try {
                $SysEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Since; ProviderName = $sysProviders } -ErrorAction Stop |
                    Where-Object { (Get-EventText $_) -match $K7IdPattern -or (Get-EventText $_) -match 'VID_0000' -or (Get-EventText $_) -match 'FiiO' })
            }
            catch {
                if ($_.Exception.Message -notmatch 'No events were found') { Write-Log WARN "System log query failed: $($_.Exception.Message)" }
            }
        }
        if ($SysEvents.Count -gt 0) {
            Write-Detail "System log entries mentioning the K7 or unknown USB devices: $($SysEvents.Count)"
            foreach ($ev in ($SysEvents | Select-Object -First 10)) {
                Write-Detail ("{0:yyyy-MM-dd HH:mm:ss}  {1} {2}  {3}" -f $ev.TimeCreated, $ev.ProviderName, $ev.Id, (Get-ShortMessage $ev.Message 140))
            }
        }
    }
    catch { Write-SectionError '6. Event logs' $_ }

    # =======================================================================
    # 7. Drivers, audio stack and audio software
    # =======================================================================
    # List FiiO driver packages in the driver store (via pnputil), confirm the Windows
    # audio services are running, check that the K7 produced an audio endpoint, report
    # the audio driver's idle power-down and the endpoint's enhancement settings, and
    # flag any audio enhancement software that could interfere. All read-only.
    Write-Section '7. Drivers, audio services and audio software'
    try {
        $pnp = Invoke-Native 'pnputil.exe' @('/enum-drivers')
        if ($pnp.Success -and $pnp.Output) {
            $blocks = (($pnp.Output -join "`n") -split "`n\s*`n")
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
                    'Several versions can co-exist. If you suspect the driver: uninstall the FiiO USB DAC driver, remove old packages, then install the current one from FiiO - with the K7 DISCONNECTED, and only connect it afterwards.'
            }
        }
        else {
            Write-Detail 'No FiiO/Thesycon driver package in the driver store (the K7 uses the Windows in-box driver).'
        }
        if ($K7Mode -eq 'Vendor') {
            # Microsoft documents that a vendor driver taking over from the in-box USB audio
            # driver while the device is connected can leave it with no sound.
            Write-Detail 'Tip: whenever you (re)install or update the FiiO driver, disconnect the K7 first and connect it only after the installer finishes.'
        }

        $uninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = @(Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName })
        foreach ($a in ($apps | Where-Object { $_.DisplayName -match 'FiiO|Thesycon' })) {
            Write-Detail "Installed: $($a.DisplayName) $(Get-ObjProp $a 'DisplayVersion')"
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

        # --- Audio enhancements and exclusive mode on each K7 output ---------------
        # Each audio output ("endpoint") has a registry key named after its GUID. An
        # "FxProperties" sub-key with values in it means audio effect processing (APOs)
        # is registered on that output; enhancement APOs are a known cause of audio
        # devices vanishing or failing to start.
        foreach ($e in $Endpoints) {
            $g = [regex]::Match($e.InstanceId, '\{[0-9A-Fa-f-]{36}\}$').Value
            if (-not $g) { continue }
            $base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\$g"
            if (-not (Test-Path -LiteralPath $base)) { $base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\$g" }
            if (-not (Test-Path -LiteralPath $base)) { continue }
            $fxCount = 0
            try { if (Test-Path -LiteralPath "$base\FxProperties") { $fxCount = @((Get-Item -LiteralPath "$base\FxProperties").GetValueNames()).Count } } catch { }
            $enhOff   = Get-RegDword "$base\Properties" $PKEY_DisableEnhancements
            $exclAllow = Get-RegDword "$base\Properties" $PKEY_ExclusiveAllow
            Write-Detail "$($e.FriendlyName): effect-processing entries=$fxCount, enhancements $(if ($enhOff -eq 1) { 'OFF' } else { 'not disabled' }), exclusive mode $(if ($exclAllow -eq 0) { 'blocked' } else { 'allowed' })"
            if ($fxCount -gt 0 -and $enhOff -ne 1) {
                Write-Finding Info 'Audio' "Audio enhancement processing is registered on '$($e.FriendlyName)' and not switched off." `
                    'As a test, turn it off: Settings > System > Sound > (K7 output) > Audio enhancements: Off. The script does not change this itself.'
            }
        }

        # --- Audio driver idle power-down ------------------------------------------
        # The Windows audio framework can power an audio device down after a period of
        # silence. The timing is stored in the device's driver key under "PowerSettings"
        # (ConservationIdleTime / PerformanceIdleTime in seconds; IdlePowerState 0 = never,
        # 3 = full power-down). Absent values mean the driver's built-in defaults apply.
        foreach ($d in @($K7All | Where-Object { $PresentIds.Contains($_.InstanceId) -and $_.Class -eq 'MEDIA' })) {
            $drvKey = Get-PropValue (Get-DevProps $d.InstanceId) 'DEVPKEY_Device_Driver'
            if (-not $drvKey) { continue }
            $psPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$drvKey\PowerSettings"
            if (-not (Test-Path -LiteralPath $psPath)) {
                Write-Detail "$($d.FriendlyName): no idle power-down override (driver defaults apply)."
                continue
            }
            $cons  = Get-RegDword $psPath 'ConservationIdleTime'
            $perf  = Get-RegDword $psPath 'PerformanceIdleTime'
            $state = Get-RegDword $psPath 'IdlePowerState'
            Write-Detail "$($d.FriendlyName): idle power-down after $perf s (mains) / $cons s (battery), state $state"
            if ($state -gt 0 -and (($perf -gt 0) -or ($cons -gt 0))) {
                Write-Finding Info 'Audio' "The K7's audio driver powers it down after $perf s of silence (on mains)." `
                    'If the K7 drops out after pauses rather than at switch-on, this is a likely cause. Ask FiiO about a driver setting for it; the script does not change it.'
            }
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
    }
    catch { Write-SectionError '7. Drivers and audio' $_ }

    # =======================================================================
    # 8. Live capture
    # =======================================================================
    # With -Watch, subscribe to WMI device create/delete/modify events, let the user
    # switch the K7 on, and log everything Windows reports for the capture window.
    # With -Trace as well, a low-level USB trace runs alongside. The result is
    # classified A-D (see the .DESCRIPTION at the top of the script).
    $Capture = $null
    $TraceResult = $null
    if (-not $Watch) {
        Write-Section '8. Live capture'
        Write-Detail 'Skipped. Run with -Watch (optionally -Trace) and switch the K7 on to record what Windows sees at that moment.'
    }
    else {
        Write-Section '8. Live capture: what Windows sees when the K7 switches on'
        try {
            # Decide whether the USB trace can safely run
            $doTrace = $false
            if ($Trace) {
                if (-not $IsAdmin) { Write-Finding Warn 'Trace' 'The USB trace needs administrator rights; continuing without it.' }
                elseif (-not $OutputFolderOk) { Write-Finding Warn 'Trace' 'No writable output folder; continuing without the USB trace.' }
                elseif (-not (Get-Command logman.exe -ErrorAction SilentlyContinue)) { Write-Finding Warn 'Trace' 'logman.exe is missing; continuing without the USB trace.' }
                elseif ($null -ne $FreeMB -and $FreeMB -lt $EtwMinFreeMB) { Write-Finding Warn 'Trace' "Only $FreeMB MB free; the USB trace needs at least $EtwMinFreeMB MB. Continuing without it." }
                else { $doTrace = $true }
            }

            Write-Line '  1. Make sure the K7 is switched OFF.' 'White'
            Write-Line '     For a faithful test, leave it off as long as it normally sits off (the failure' 'White'
            Write-Line '     tends to follow a cold switch-on, not a quick off/on).' 'White'
            Write-Line '  2. Press Enter, then switch the K7 ON within 10 seconds and leave it alone.' 'White'
            Write-Line "  3. The capture runs for $WatchSeconds seconds$(if ($doTrace) { ', with a USB trace' })." 'White'
            $started = $true
            try { [void](Read-Host '  Press Enter to start') }
            catch {
                Write-Finding Warn 'Capture' 'Could not read from the keyboard (no interactive console), so the live capture was skipped.'
                $started = $false
            }

            if ($started) {
                $log = New-Object System.Collections.Generic.List[object]
                $capPnp = @()
                $CaptureStart = Get-Date
                # Inner try/finally: the WMI subscriptions and the trace are ALWAYS removed,
                # even if something fails or Ctrl+C is pressed during the capture.
                try {
                    if ($doTrace) {
                        if (Start-UsbTrace) { Write-Line "  USB trace running -> $TracePath" 'DarkGray' }
                        else {
                            Write-Finding Warn 'Trace' 'The USB trace could not be started (see the log); continuing with the normal capture.'
                            $doTrace = $false
                        }
                    }

                    foreach ($s in $CaptureSourceIds) { Unregister-Event -SourceIdentifier $s -ErrorAction Ignore }
                    Get-Event -ErrorAction SilentlyContinue | Where-Object { $CaptureSourceIds -contains $_.SourceIdentifier } | Remove-Event -ErrorAction SilentlyContinue

                    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity'" -SourceIdentifier 'K7W_Create' -ErrorAction Stop | Out-Null
                    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity'" -SourceIdentifier 'K7W_Delete' -ErrorAction Stop | Out-Null
                    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.PNPDeviceID LIKE 'USB%'" -SourceIdentifier 'K7W_Modify' -ErrorAction Stop | Out-Null

                    Write-Line '  Capturing... switch the K7 ON now.' 'Green'
                    $deadline = $CaptureStart.AddSeconds($WatchSeconds)
                    while ((Get-Date) -lt $deadline) {
                        $evt = Wait-Event -Timeout 1
                        if (-not $evt) { continue }
                        if ($CaptureSourceIds -contains $evt.SourceIdentifier) {
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
                            Write-Line ("    +{0,5:N1}s  {1,-8} {2}  [{3}, code {4}]" -f ($rec.Time - $CaptureStart).TotalSeconds, $rec.Event, $rec.Name, $rec.Status, $rec.ErrorCode) $colour
                        }
                        Remove-Event -EventIdentifier $evt.EventIdentifier -ErrorAction SilentlyContinue
                    }
                }
                finally {
                    foreach ($s in $CaptureSourceIds) { Unregister-Event -SourceIdentifier $s -ErrorAction Ignore }
                    if ($script:EtwRunning) { Stop-UsbTrace }
                }

                # Kernel-PnP log for the same window (catches anything the WMI poll missed)
                try {
                    $capPnp = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; StartTime = $CaptureStart } -ErrorAction Stop |
                        Where-Object { (Get-EventText $_) -match 'USB\\' })
                }
                catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-Log WARN "Capture PnP log read failed: $($_.Exception.Message)" } }
                if ($capPnp.Count -gt 0) {
                    Write-Line '  Kernel-PnP log during the capture:'
                    foreach ($ev in ($capPnp | Sort-Object TimeCreated)) {
                        Write-Detail ("{0:HH:mm:ss}  ID {1}  {2}" -f $ev.TimeCreated, $ev.Id, (Get-ShortMessage $ev.Message 150))
                    }
                }

                # --- USB trace analysis ------------------------------------------------
                if ($doTrace) {
                    Write-Line ''
                    Write-Line '  USB trace analysis:' 'White'
                    $TraceResult = Get-UsbTraceAnalysis
                    $traceSize = 0
                    if (Test-Path -LiteralPath $TracePath) { $traceSize = [math]::Round((Get-Item -LiteralPath $TracePath).Length / 1KB) }
                    Write-Detail "Trace file: $TracePath ($traceSize KB, $($TraceResult.Total) events)"
                    foreach ($p in $TraceResult.ByProvider) { Write-Detail "  $p" }
                    if ($TraceResult.Total -eq 0) {
                        Write-Finding Warn 'Trace' 'The USB trace recorded no events.' 'The trace may not have started correctly; see the log file.'
                    }
                    elseif ($TraceResult.Suspicious.Count -gt 0) {
                        Write-Finding Warn 'Trace' "The USB trace contains $($TraceResult.Suspicious.Count) event(s) that suggest a USB-level problem." `
                            'They are listed below. This is a pointer, not proof: send the .etl file to FiiO support for expert analysis.'
                        foreach ($s in ($TraceResult.Suspicious | Select-Object -First 25)) {
                            Write-Detail ("{0:HH:mm:ss.fff}  {1} id {2}  [{3}]  {4} {5}" -f $s.Time, ($s.Provider -replace '^Microsoft-Windows-USB-', ''), $s.Id, $s.Why, $s.Task, $s.Message)
                        }
                    }
                    else {
                        Write-Finding OK 'Trace' 'The USB trace shows no USB-level errors during the capture.'
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
                        'WINDOWS-SIDE fault in the audio stack (Audio Endpoint Builder or an audio enhancement/APO). Test with audio utilities removed and enhancements off.'
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
                        'Send the report (and the .etl trace, if you used -Trace) to FiiO support with the capture section.'
                }
                $Capture = [pscustomobject]@{ Verdict = $verdict; Events = $log }
                Write-Log INFO "Capture verdict: $verdict ($($log.Count) WMI events, $($capPnp.Count) PnP log events)"
            }
        }
        catch { Write-SectionError '8. Live capture' $_ }
    }

    # =======================================================================
    # 9. Verdict
    # =======================================================================
    # Combine the live capture result (if any) with the evidence from sections 2-6 into
    # a plain-language conclusion: Windows side, USB link side, or most likely hardware.
    Write-Section '9. Verdict'
    try {
        $WindowsSide = ($K7StartFailures.Count -gt 0) -or ($null -ne $K7PresentError)
        $LinkSide    = ($UnknownEvents.Count -gt 0) -or ($Unknown.Count -gt 0)

        if ($Capture -and $Capture.Verdict -ne 'OK' -and $Capture.Verdict -ne 'Unclear') {
            switch ($Capture.Verdict) {
                'A' { Write-Line '  The live capture shows the K7 never attached. Cause: K7 / cable / port, not Windows.' 'Red' }
                'B' { Write-Line '  The live capture shows a failed USB enumeration. Cause: USB link start-up (K7 timing, cable, port or hub).' 'Red' }
                'C' { Write-Line '  The live capture shows Windows rejecting the K7 driver start. Cause: Windows / driver.' 'Red' }
                'D' { Write-Line '  The live capture shows the audio endpoint missing. Cause: Windows audio stack or audio software.' 'Red' }
            }
            if ($TraceResult -and $TraceResult.Suspicious.Count -gt 0 -and $Capture.Verdict -in 'A', 'B') {
                Write-Line '  The USB trace also recorded USB-level errors: keep the .etl file for FiiO support.' 'Red'
            }
        }
        elseif ($WindowsSide) {
            Write-Line '  Evidence points to WINDOWS: it saw the K7 and failed to start its driver.' 'Red'
        }
        elseif ($LinkSide) {
            Write-Line '  Evidence points to the USB LINK: Windows recorded failed enumerations (Unknown USB Device),' 'Yellow'
            Write-Line '  not driver failures. The K7 connects, but does not answer correctly on the first attempt.' 'Yellow'
            Write-Line '  A second switch-on gives Windows a fresh attach, which is why the off/on cycle works.' 'Yellow'
        }
        elseif ($EventLogBlind) {
            Write-Line '  No failure is recorded, but the event log did not capture even the K7''s successful attach,' 'Yellow'
            Write-Line '  so its silence is not proof. Run -Watch -Trace (elevated) at the moment the K7 fails for real evidence.' 'Yellow'
        }
        else {
            Write-Line '  Windows holds no record of a failed start or failed enumeration for the K7.' 'Yellow'
            Write-Line '  When the K7 fails, Windows most likely never sees it attach at all. That points to the K7' 'Yellow'
            Write-Line '  (its USB receiver not starting up on the first power-on), the cable, or the port rather than' 'Yellow'
            Write-Line '  Windows. Run with -Watch -Trace at the moment it fails to confirm.' 'Yellow'
        }

        Write-Line ''
        Write-Line '  Ruling hardware in or out:' 'White'
        Write-Line '   1. Connect the K7 directly to a REAR motherboard USB port (try a USB 2.0 port if the board has one).'
        Write-Line '   2. Try a port on a DIFFERENT root hub or controller (see section 4) - a built-in hub can be the weak link.'
        Write-Line '   3. Use a different, short USB-B cable.'
        Write-Line '   4. Test the K7 on another computer (or a phone/tablet with an adapter) with a cold switch-on.'
        Write-Line '      Fails there too -> K7 hardware/firmware: contact FiiO or the retailer under warranty.'
        Write-Line '      Works there     -> this PC: apply -Fix, then work through the Windows items above.'

        $counts = $Findings | Group-Object Level | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-Line ''
        Write-Line ('  Findings - ' + ($counts -join ', '))
    }
    catch { Write-SectionError '9. Verdict' $_ }

    # =======================================================================
    # 10. Fixes
    # =======================================================================
    # Only runs with -Fix. The order of safety steps for EVERY change is:
    #   1. ask (or -Force / -DryRun)       2. check it is on the allow-list
    #   3. make a restore point (first change only)
    #   4. record the original value in the backup file and save it
    #   5. make the change                 6. read the value back to verify it
    # If step 4 fails, the change is not made. Nothing here touches firmware, drivers
    # or Windows updates.
    if ($Fix) {
        Write-Section "10. Fixes$(if ($DryRun) { ' (DRY RUN - nothing will be changed)' })"
        if ($ChangesBlocked) {
            Write-Line '  Fixes are disabled for this run: a pre-flight safety check failed (see section 0).' 'Red'
        }
        elseif ($RestartPending -and -not $DryRun -and -not (Confirm-Step 'A Windows restart is pending. Continue with fixes anyway? (Restarting first is recommended)')) {
            Write-Line '  Fixes cancelled. Restart Windows, then run -Fix again.' 'Yellow'
        }
        elseif (-not (Initialize-Backup $SchemeGuid)) {
            Write-Line "  Fixes cancelled: the backup file could not be created or verified at $BackupPath." 'Red'
            Write-Line '  No change is ever made without a working backup. Use -OutputFolder to choose another folder.' 'Red'
            $script:ExitCode = 2
        }
        else {
            try {
                if (-not $DryRun) { Write-Line "  Each change is recorded in $BackupPath so -RestoreFrom can undo it." }
                $changeCount = 0; $failCount = 0
                # Set to $true if the user declines to continue without a restore point;
                # every later fix then skips itself. "$script:" means the variable belongs
                # to the whole script, so functions can change it too.
                $script:Aborted = $false

                # Changes a power-plan setting (AC and DC) with backup and verification
                function Set-PowerValueSafely {
                    param([string]$Name, [string]$Sub, [string]$Setting, $Current, [int]$NewValue)
                    if (-not (Test-AllowedPowerSetting $Sub $Setting)) { Write-Log ERROR "Refused power setting $Sub/$Setting (not allowed)"; return $false }
                    $scheme = if ($SchemeGuid) { $SchemeGuid } else { 'SCHEME_CURRENT' }
                    $entry = [pscustomobject]@{ Name = $Name; Sub = $Sub; Setting = $Setting; AC = $Current.AC; DC = $Current.DC }
                    if (-not $DryRun) {
                        $script:Backup.Power.Add($entry)
                        if (-not (Save-Backup)) { [void]$script:Backup.Power.Remove($entry); return $false }
                    }
                    $r1 = Invoke-Native 'powercfg.exe' @('/setacvalueindex', $scheme, $Sub, $Setting, "$NewValue") -Change
                    $r2 = Invoke-Native 'powercfg.exe' @('/setdcvalueindex', $scheme, $Sub, $Setting, "$NewValue") -Change
                    if (-not ($r1.Success -and $r2.Success)) { Write-Line "    $Name : powercfg reported an error (see log)." 'Yellow'; return $false }
                    if ($DryRun) { return $true }
                    $after = Get-PowerSetting $Sub $Setting $scheme
                    if ($after.AC -ne $NewValue) { Write-Line "    $Name : the new value did not read back correctly (now $($after.AC))." 'Yellow'; Write-Log ERROR "$Name verify failed: AC=$($after.AC)"; return $false }
                    Write-Log CHANGE "$Name set to $NewValue (was AC=$($Current.AC) DC=$($Current.DC)), verified"
                    return $true
                }

                # Sets a registry DWORD with allow-list check, backup first, and verification
                function Set-RegDwordSafely {
                    param([string]$Path, [string]$Name, [int]$Value)
                    if (-not (Test-AllowedRegistryTarget $Path $Name)) {
                        Write-Line "    REFUSED: $Path\$Name is not on the list of settings this script may change." 'Red'
                        Write-Log ERROR "Refused registry change $Path\$Name (not allowed)"
                        return $false
                    }
                    if (-not (Test-Path -LiteralPath $Path)) { Write-Log WARN "Registry key missing: $Path"; return $false }
                    $old = Get-RegDword $Path $Name
                    if ($DryRun) {
                        Write-Host "    [DRY RUN] would set $Path\$Name = $Value (now: $(if ($null -eq $old) { 'not set' } else { $old }))" -ForegroundColor Magenta
                        Write-Log DRYRUN "Would set $Path\$Name = $Value"
                        return $true
                    }
                    $entry = [pscustomobject]@{ Path = $Path; Name = $Name; Existed = ($null -ne $old); Value = $old }
                    $script:Backup.Registry.Add($entry)
                    if (-not (Save-Backup)) { [void]$script:Backup.Registry.Remove($entry); return $false }
                    try {
                        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        # The change failed, so the backup entry is not needed: remove it again
                        [void]$script:Backup.Registry.Remove($entry); [void](Save-Backup)
                        Write-Line "    Could not set $Path\$Name : $($_.Exception.Message)" 'Yellow'
                        Write-Log ERROR "Registry change failed $Path\$Name : $($_.Exception.Message)"
                        return $false
                    }
                    if ((Get-RegDword $Path $Name) -ne $Value) { Write-Line "    $Path\$Name did not read back correctly." 'Yellow'; Write-Log ERROR "Verify failed $Path\$Name"; return $false }
                    Write-Log CHANGE "Set $Path\$Name = $Value (was $(if ($null -eq $old) { 'not set' } else { $old })), verified"
                    return $true
                }

                # Runs before each fix: gets the restore point the first time. Returns $false
                # (and stops all further fixes) if the user declines to continue without one.
                function Request-ChangeAllowed {
                    if ($script:Aborted) { return $false }
                    if (-not (Confirm-RestorePoint)) { $script:Aborted = $true; return $false }
                    return $true
                }

                # F1 + F2: power plan settings
                $planChanged = $false
                if ($UsbSelectiveSuspendOn -or ($null -ne $ss.DC -and $ss.DC -eq 1)) {
                    if ((Confirm-Step 'Disable USB selective suspend in the active power plan?') -and (Request-ChangeAllowed)) {
                        if (Set-PowerValueSafely 'USB selective suspend' $GUID_SUB_USB $GUID_USB_SS $ss 0) { $planChanged = $true; $changeCount++; Write-Line '    USB selective suspend disabled.' 'Green' } else { $failCount++ }
                    }
                }
                if ($LspmOn -or ($null -ne $ls.DC -and $ls.DC -gt 0)) {
                    if ((Confirm-Step 'Turn off PCI Express Link State Power Management?') -and (Request-ChangeAllowed)) {
                        if (Set-PowerValueSafely 'PCIe LSPM' $GUID_SUB_PCIE $GUID_PCIE_LSPM $ls 0) { $planChanged = $true; $changeCount++; Write-Line '    PCIe Link State Power Management off.' 'Green' } else { $failCount++ }
                    }
                }
                if ($planChanged) {
                    $scheme = if ($SchemeGuid) { $SchemeGuid } else { 'SCHEME_CURRENT' }
                    [void](Invoke-Native 'powercfg.exe' @('/setactive', $scheme) -Change)
                }

                # F3: device power management on hubs and the K7
                if ($TurnOffAllowed.Count -gt 0) {
                    if ((Confirm-Step "Stop Windows turning off $($TurnOffAllowed.Count) USB hub/device(s) to save power?") -and (Request-ChangeAllowed)) {
                        foreach ($t in $TurnOffAllowed) {
                            $e = Find-MSPowerEntry $MSPower $t.InstanceId
                            if (-not $e) { continue }
                            if ($e.InstanceName -notmatch '^USB\\') { Write-Log ERROR "Refused MSPower change for non-USB $($e.InstanceName)"; continue }
                            if ($DryRun) {
                                Write-Host "    [DRY RUN] would clear 'allow turn off' on $($t.FriendlyName)" -ForegroundColor Magenta
                                Write-Log DRYRUN "Would clear MSPower on $($e.InstanceName)"
                                continue
                            }
                            $entry = [pscustomobject]@{ InstanceName = $e.InstanceName; Enable = [bool]$e.Enable }
                            $script:Backup.MSPower.Add($entry)
                            if (-not (Save-Backup)) { [void]$script:Backup.MSPower.Remove($entry); $failCount++; continue }
                            try {
                                Set-CimInstance -InputObject $e -Property @{ Enable = $false } -ErrorAction Stop
                                $check = Find-MSPowerEntry @(Get-MSPowerEntries) $t.InstanceId
                                if ($check -and -not $check.Enable) {
                                    Write-Log CHANGE "Cleared 'allow turn off' on $($e.InstanceName), verified"
                                    Write-Line "    $($t.FriendlyName): power-down disabled." 'Green'
                                    $changeCount++
                                }
                                else { Write-Line "    $($t.FriendlyName): the change did not read back correctly." 'Yellow'; $failCount++ }
                            }
                            catch {
                                [void]$script:Backup.MSPower.Remove($entry); [void](Save-Backup)
                                Write-Line "    $($t.FriendlyName): $($_.Exception.Message)" 'Yellow'
                                Write-Log ERROR "MSPower change failed on $($e.InstanceName): $($_.Exception.Message)"
                                $failCount++
                            }
                        }
                    }
                }

                # F3b: selective suspend / idle flags on the K7's own device entries
                if ($K7Roots.Count -gt 0) {
                    $pendingFlags = @()
                    foreach ($r in $K7Roots) {
                        $dp = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($r.InstanceId)\Device Parameters"
                        if (-not (Test-Path -LiteralPath $dp)) { continue }
                        foreach ($n in 'EnhancedPowerManagementEnabled', 'SelectiveSuspendEnabled', 'AllowIdleIrpInD3') {
                            $v = Get-RegDword $dp $n
                            # Only the core flag is worth creating; the others matter only when a driver already set them
                            if (($n -eq 'EnhancedPowerManagementEnabled' -and $v -ne 0) -or ($n -ne 'EnhancedPowerManagementEnabled' -and $null -ne $v -and $v -ne 0)) {
                                $pendingFlags += [pscustomobject]@{ Path = $dp; Name = $n; Id = $r.InstanceId }
                            }
                        }
                    }
                    if ($pendingFlags.Count -gt 0 -and (Confirm-Step 'Disable selective suspend / idle power-down flags on the K7 device entries?') -and (Request-ChangeAllowed)) {
                        foreach ($x in $pendingFlags) {
                            if (Set-RegDwordSafely $x.Path $x.Name 0) { $changeCount++; if (-not $DryRun) { Write-Line "    $($x.Id): $($x.Name) = 0" 'Green' } } else { $failCount++ }
                        }
                    }
                }

                # F4: phantom devices. Removing an entry for a DISCONNECTED device is harmless:
                # Windows recreates it the next time the device connects. It cannot be undone by
                # -RestoreFrom (there is nothing to restore), so each one is re-checked first.
                $Stale = @()
                $Stale += @($K7Phantoms | Where-Object { $_.Class -ne 'AudioEndpoint' -and $_.InstanceId -like 'USB*' })
                $Stale += @($Unknown | Where-Object { -not $PresentIds.Contains($_.InstanceId) })
                $Stale = @($Stale | Where-Object { $_.InstanceId -match $AllowedRemovePattern } | Sort-Object InstanceId -Unique)
                if ($Stale.Count -gt 0 -and $Build -ge 19041) {
                    foreach ($s in $Stale) { Write-Detail "Disconnected entry: $($s.FriendlyName) ($($s.InstanceId))" }
                    if ((Confirm-Step "Remove $($Stale.Count) disconnected K7 / Unknown USB Device entries (Windows recreates them on next connect)?") -and (Request-ChangeAllowed)) {
                        $presentNow = Get-PresentIdSet   # fresh check, in case the K7 was switched on meanwhile
                        foreach ($s in $Stale) {
                            if ($presentNow.Contains($s.InstanceId)) {
                                Write-Line "    Skipped $($s.InstanceId): it is connected now." 'Yellow'
                                Write-Log WARN "Skipped removal of $($s.InstanceId): present"
                                continue
                            }
                            $r = Invoke-Native 'pnputil.exe' @('/remove-device', $s.InstanceId) -Change
                            if ($r.DryRun) { continue }
                            if ($r.Success) {
                                $script:Backup.Removed.Add([pscustomobject]@{ InstanceId = $s.InstanceId; Name = $s.FriendlyName; When = (Get-Date).ToString('s') })
                                [void](Save-Backup)
                                Write-Line "    Removed $($s.InstanceId)" 'Green'
                                $changeCount++
                            }
                            else { Write-Line "    Could not remove $($s.InstanceId) (pnputil exit $($r.ExitCode))." 'Yellow'; $failCount++ }
                        }
                    }
                }

                # F5: Fast Startup
                if ($FastStartupOn) {
                    if ((Confirm-Step 'Disable Fast Startup? (only matters if the K7 fails after a cold boot)') -and (Request-ChangeAllowed)) {
                        if (Set-RegDwordSafely 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0) {
                            $changeCount++
                            if (-not $DryRun) { Write-Line '    Fast Startup disabled.' 'Green' }
                        }
                        else { $failCount++ }
                    }
                }

                # F6: restart a present-but-failed K7, then rescan
                $nowBad = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match $AllowedRestartPattern -and $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })
                foreach ($nb in $nowBad) {
                    if ((Confirm-Step "Restart the failed device $($nb.FriendlyName)?") -and (Request-ChangeAllowed)) {
                        $r = Invoke-Native 'pnputil.exe' @('/restart-device', $nb.InstanceId) -Change
                        if ($r.Success) { $changeCount++ } else { Write-Line "    Restart failed (pnputil exit $($r.ExitCode))." 'Yellow'; $failCount++ }
                    }
                }
                if ($changeCount -gt 0 -and -not $script:Aborted) {
                    # A rescan asks Windows to look for hardware changes. It changes no settings.
                    [void](Invoke-Native 'pnputil.exe' @('/scan-devices') -Change)
                    if (-not $DryRun) { Write-Line '    Hardware rescan triggered.' }
                }

                # Advice that the script deliberately does not automate
                if ($AffectedBuild -and $K7Mode -eq 'UAC1') {
                    Write-Line ''
                    Write-Line '  Not automated: the K7 runs on usbaudio.sys (UAC 1.0), which Microsoft''s open Code 10 issue affects.' 'Yellow'
                    Write-Line '  Options: install the current FiiO USB DAC driver from fiio.com (K7 disconnected during install),' 'Yellow'
                    Write-Line '  or wait for the Microsoft fix. This script never swaps or replaces Windows drivers.' 'Yellow'
                }

                # Summary
                Write-Line ''
                if ($script:Aborted) { Write-Line '  Fixes stopped at your request (no restore point). Changes made before that point are listed above.' 'Yellow' }
                if ($DryRun) {
                    Write-Line "  DRY RUN complete: $changeCount change(s) would be made. Nothing was changed." 'Magenta'
                }
                elseif ($changeCount -gt 0 -or ($script:Backup.Power.Count + $script:Backup.Registry.Count + $script:Backup.MSPower.Count) -gt 0) {
                    [void](Save-Backup)
                    Write-Line "  $changeCount change(s) made$(if ($failCount) { ", $failCount failed (see the log)" })." $(if ($failCount) { 'Yellow' } else { 'Green' })
                    Write-Line "  Backup saved: $BackupPath" 'Green'
                    Write-Line "  Undo with:    .\Diagnose-FiiOK7.ps1 -RestoreFrom `"$BackupPath`"" 'Green'
                    if ($script:RestorePointState -eq 'Created') { Write-Line '  A System Restore point was also created before the first change.' 'Green' }
                    Write-Line '  Restart Windows, then test a cold switch-on of the K7 (ideally with -Watch -Trace).' 'White'
                }
                else {
                    Write-Line '  No settings changed.'
                }
                if ($failCount -gt 0) { $script:ExitCode = 1 }
            }
            catch { Write-SectionError '10. Fixes' $_ }
        }
    }
    elseif (@($Findings | Where-Object { $_.Level -in 'Warn', 'Fault' }).Count -gt 0) {
        Write-Line ''
        Write-Line '  Run again with -Fix -DryRun to preview the available fixes, -Fix to apply them, or -Watch -Trace to capture a failing switch-on.' 'White'
    }

    Write-Line ''
    Write-Line "Report saved: $ReportPath" 'Cyan'
    Write-Line "Log saved:    $LogPath" 'Cyan'
}
catch {
    # Anything that escaped every other handler ends up here
    $script:ExitCode = 1
    Write-Host "Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log ERROR "Fatal: $($_.Exception.Message) | $($_.ScriptStackTrace -replace '\r?\n', ' <- ')"
}
finally {
    # Always runs: stop the trace, remove WMI subscriptions, release the lock, close the transcript
    Invoke-Cleanup
    # The exit code is set here, inside "finally", because several places above stop the
    # script early with "return" (e.g. a rejected backup file). A "return" ends the script
    # straight after this block, so an exit placed after it would never be reached and
    # every run would report success (0) to whatever started it.
    exit $script:ExitCode
}
