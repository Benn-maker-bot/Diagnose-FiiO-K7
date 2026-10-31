# Diagnose FiiO K7

A PowerShell script that works out **why Windows 11 sometimes fails to recognise a FiiO K7 USB DAC/amp when the K7 is switched on**, and can optionally apply safe, reversible settings fixes.

## The problem it solves

A common complaint is that the K7 is not picked up when it is powered on after Windows has started (or after a cold boot), and only works after switching it off and on again. The cause could be in any of several places, and the fix depends on which:

| Result | What Windows sees | Where the fault is |
| -------- | ------------------- | -------------------- |
| **A** | No USB attach at all | K7, cable or port (hardware path) |
| **B** | "Unknown USB Device" (Device Descriptor Request Failed) | USB link-level enumeration failure: K7 start-up timing, cable, port, hub or power |
| **C** | The K7, but it fails to start (Code 10, 28, 39, 52 ...) | Windows side: driver or a known Windows issue |
| **D** | The K7 starts, but no audio output device appears | Windows audio stack or audio software |

The script gathers evidence and tells you which of these you are dealing with, so you know whether to blame Windows, the cable/port, or the K7 itself.

## What it checks

- **Pre-flight safety checks**: Windows version, 64-bit PowerShell, administrator rights, a writable output folder, the Windows tools it needs, and whether a restart is pending.
- **Windows build and updates**, including Insider channel and Microsoft's open known issue where some USB Audio Class 1.0 devices fail with Code 10 after recent updates. The script only warns about this if the K7 is actually using the affected in-box driver.
- **Every K7 device instance** (connected and "phantom"): driver, problem code, last arrival/removal time.
- **"Unknown USB Device" entries** left behind by failed enumerations.
- **The USB path** from the K7 up to the host controller, flagging separate hubs (front panel, dock, monitor) versus hubs built into the motherboard.
- **Power management**: USB selective suspend, PCIe Link State Power Management, Fast Startup, and each hub's "allow the computer to turn off this device" setting.
- **Event logs** (Kernel-PnP and System) for K7 start failures and failed enumerations.
- **Drivers and audio stack**: FiiO driver packages, audio services, the K7's audio endpoint, and audio software that can interfere (Sonic Studio, Nahimic, Voicemeeter, Equalizer APO, Krisp and others).
- **Audio enhancements and idle power-down**: whether enhancement processing is active on the K7's output, and whether the audio driver is set to power the K7 down after a period of silence (reported only, never changed).
- **Low-level USB trace** (optional, `-Watch -Trace`): records every step of the USB conversation while the K7 switches on, using the trace providers built into Windows' own USB drivers, and highlights steps that failed.

## Requirements

- Windows 10/11 with PowerShell 5.1 or later (Windows PowerShell or PowerShell 7).
- Administrator rights for the complete picture. The read-only report and `-DryRun` previews work without them, but cannot read some event logs or device power flags. `-Fix`, `-RestoreFrom` and `-Trace` relaunch themselves elevated automatically (Windows asks for permission).

## Usage

Run from the repository folder. If you are new to this, follow the steps in order:

```powershell
# 1. Read-only report (changes nothing). Always start here.
.\Diagnose-FiiOK7.ps1

# 2. Live capture: switch the K7 on when prompted and see what Windows reports
.\Diagnose-FiiOK7.ps1 -Watch

# 3. Live capture plus a low-level USB trace (best evidence for FiiO support)
.\Diagnose-FiiOK7.ps1 -Watch -Trace

# 4. Preview the fixes: shows exactly what would change, changes nothing
.\Diagnose-FiiOK7.ps1 -Fix -DryRun

# 5. Apply the fixes, confirming each one
.\Diagnose-FiiOK7.ps1 -Fix

# 6. Undo the changes recorded in a backup file
.\Diagnose-FiiOK7.ps1 -RestoreFrom ".\reports\FiiO-K7-Backup-20261031-0800.json"
```

In VS Code, the same modes are available from the Run and Debug panel (Ctrl+Shift+D): pick one from the drop-down and press F5.

If Windows blocks the script:

```powershell
Unblock-File .\Diagnose-FiiOK7.ps1
powershell -ExecutionPolicy Bypass -File .\Diagnose-FiiOK7.ps1
```

### Getting a useful `-Watch` result

The fault usually follows a *cold* switch-on, so leave the K7 off for as long as it normally sits off, run `-Watch`, press Enter, then switch the K7 on within 10 seconds. If the first attempt works, run it again on a day the problem actually occurs.

Add `-Trace` to also record a USB trace. The trace is written to a `.etl` file (capped at 256 MB, and only started if at least 1 GB is free) and is always stopped when the capture ends, including after an error or Ctrl+C. The script lists the trace events that look like failures. That list is a pointer for a person to follow up, not proof: send the `.etl` file to FiiO support for expert analysis.

### Parameters

| Parameter | Purpose | Default |
| ----------- | --------- | --------- |
| `-Watch` | Live capture of what Windows sees when the K7 switches on | off |
| `-WatchSeconds` | Capture length in seconds (15-600) | 60 |
| `-Trace` | With `-Watch`: also record a low-level USB trace | off |
| `-Fix` | Offer to apply fixes, each confirmed individually | off |
| `-DryRun` | With `-Fix` / `-RestoreFrom`: show what would change, change nothing | off |
| `-Force` | Answer yes to every prompt (safety checks still apply) | off |
| `-NoRestorePoint` | Skip the System Restore point `-Fix` makes before its first change | off |
| `-Days` | Days of event log history to search (1-90) | 14 |
| `-RestoreFrom` | Backup JSON to revert | none |
| `-OutputFolder` | Where reports, logs, backups and traces are written | `reports` beside the script |

## Safety

Without `-Fix` or `-RestoreFrom` the script only reads from the system. When it does make changes, it follows these rules:

1. **Pre-flight checks first.** Changes are disabled entirely on 32-bit PowerShell under 64-bit Windows (it sees a redirected copy of the registry), on Windows older than 10 version 2004, if a needed Windows tool is missing, if no writable folder is available for the backup, or if another copy of the script is already making changes.
2. **Preview with `-DryRun`.** Every change can be listed without being made.
3. **Ask before each change**, unless `-Force` is used. If the prompt can't be shown, the answer is treated as "no".
4. **Restore point.** A Windows System Restore point is made before the first change. If Windows can't make one, the script says so and asks whether to continue.
5. **Backup before change.** The original value is saved to the backup file, which is written atomically and checked, *before* each change. If the backup can't be saved, that change is not made.
6. **Allow-list.** The script can only change the specific settings listed below. Anything else is refused, and that includes the contents of a backup file: an edited or damaged backup cannot be used to change other settings.
7. **Verify after change.** Each new value is read back. A mismatch is reported and logged.
8. **Always clean up.** Whatever happens, the USB trace is stopped, event subscriptions are removed and the lock is released.

## What `-Fix` can change

Each change is optional, asked about first, and recorded in a backup so `-RestoreFrom` can reverse it:

- Disable USB selective suspend in the active power plan
- Turn off PCIe Link State Power Management
- Stop Windows powering down USB hubs/devices on the K7's path
- Clear selective suspend / idle power-down flags on the K7's device entries
- Remove disconnected (phantom) K7 and "Unknown USB Device" entries. Each one is checked again just before removal and skipped if it is connected. This one can't be undone with `-RestoreFrom`, but nothing is lost: Windows recreates the entry the next time the device connects.
- Disable Fast Startup
- Restart a K7 device that is present but failed, then trigger a hardware rescan

It never changes firmware, installs or removes drivers, or touches Windows Update. Where a driver change would help, for example moving the K7 off the in-box USB Audio Class 1.0 driver hit by the September 2026 Code 10 issue, the script tells you what to do instead of doing it. Community tools exist that swap Windows' audio driver to work around that issue, but replacing system drivers is outside what this script will do automatically.

## Output

Each run writes these files to the `reports` folder:

| File | Contents |
| ------ | --------- |
| `FiiO-K7-Report-<time>.txt` | Transcript of everything shown on screen |
| `FiiO-K7-Log-<time>.log` | Detailed timestamped log: every check, every command run and its exit code, every change (marked `CHANGE`), and every error, including ones not shown on screen |
| `FiiO-K7-Backup-<time>.json` | (`-Fix`) Original value of every setting changed, for `-RestoreFrom` |
| `FiiO-K7-UsbTrace-<time>.etl` | (`-Trace`) Raw USB trace for FiiO or Microsoft support |

The `reports` folder is git-ignored because it contains machine-specific details. If you contact FiiO support, attach the report and log (and the `.etl` trace if you used `-Trace`).

The script also sets an exit code, which is useful when it is run from another tool: `0` = completed, `1` = an unexpected error occurred (see the log), `2` = refused to run because a safety check failed.

## Project layout

| File | Purpose |
| ------ | --------- |
| `Diagnose-FiiOK7.ps1` | The diagnostic script |
| `.vscode/launch.json` | VS Code Run and Debug configurations for the five main modes |
| `cspell.json` | Spell-checker dictionary for technical terms |
| `.gitignore` | Keeps generated reports out of the repository |

## Notes and limitations

- Device IDs matched are FiiO's USB vendor ID `2972` and XMOS `20B1` (the K7's USB receiver chip, which a K7 in firmware-update mode may show).
- The known-issue KB list reflects Microsoft's status at the time of writing and will age as fixes ship.
- Some results are inconclusive by nature: if Windows logs nothing, the K7 may never have signalled a connection. Use `-Watch -Trace` to confirm.
- Reading power settings relies on `powercfg`'s English output. On non-English Windows those checks report "could not read" rather than guessing, and the matching fixes are skipped.
- Spotting failures in the USB trace is heuristic. It flags events marked as warnings or errors, events whose task or message mentions a failure, and events that carry a Windows error status code. A healthy switch-on produces hundreds of routine events and should flag none.
- Run it at your own risk; fixes only change standard Windows power and device settings, and are reversible via the backup and the restore point.
