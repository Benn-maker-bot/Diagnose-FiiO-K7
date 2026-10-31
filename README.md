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

- **Windows build and updates**, including Insider channel and Microsoft's open known issue where some USB Audio Class 1.0 devices fail with Code 10 after recent updates. The script only warns about this if the K7 is actually using the affected in-box driver.
- **Every K7 device instance** (connected and "phantom"): driver, problem code, last arrival/removal time.
- **"Unknown USB Device" entries** left behind by failed enumerations.
- **The USB path** from the K7 up to the host controller, flagging separate hubs (front panel, dock, monitor) versus hubs built into the motherboard.
- **Power management**: USB selective suspend, PCIe Link State Power Management, Fast Startup, and each hub's "allow the computer to turn off this device" setting.
- **Event logs** (Kernel-PnP and System) for K7 start failures and failed enumerations.
- **Drivers and audio stack**: FiiO driver packages, audio services, the K7's audio endpoint, and audio software that can interfere (Sonic Studio, Nahimic, Voicemeeter, Equalizer APO, Krisp and others).

## Requirements

- Windows 10/11 with PowerShell 5.1 or later (Windows PowerShell or PowerShell 7).
- Administrator rights for the complete picture. The read-only report works without them but cannot read some event logs or device power flags. `-Fix` and `-RestoreFrom` relaunch themselves elevated automatically.

## Usage

Run from the repository folder:

```powershell
# 1. Read-only report (changes nothing)
.\Diagnose-FiiOK7.ps1

# 2. Live capture: switch the K7 on when prompted and see what Windows reports
.\Diagnose-FiiOK7.ps1 -Watch

# 3. Report, then offer each fix with a Y/N prompt
.\Diagnose-FiiOK7.ps1 -Fix

# 4. Undo the changes recorded in a backup file
.\Diagnose-FiiOK7.ps1 -RestoreFrom ".\reports\FiiO-K7-Backup-20261031-0800.json"
```

If Windows blocks the script:

```powershell
Unblock-File .\Diagnose-FiiOK7.ps1
powershell -ExecutionPolicy Bypass -File .\Diagnose-FiiOK7.ps1
```

### Getting a useful `-Watch` result

The fault usually follows a *cold* switch-on, so leave the K7 off for as long as it normally sits off, run `-Watch`, press Enter, then switch the K7 on within 10 seconds. If the first attempt works, run it again on a day the problem actually occurs.

### Parameters

| Parameter | Purpose | Default |
| ----------- | --------- | --------- |
| `-Watch` | Live capture of what Windows sees when the K7 switches on | off |
| `-WatchSeconds` | Capture length in seconds (15-600) | 60 |
| `-Fix` | Offer to apply fixes, each confirmed individually | off |
| `-Force` | Answer yes to every `-Fix` prompt | off |
| `-Days` | Days of event log history to search (1-90) | 14 |
| `-RestoreFrom` | Backup JSON to revert | none |
| `-OutputFolder` | Where reports and backups are written | `reports` beside the script |

## What `-Fix` can change

Each change is optional, asked about first, and recorded in a backup so `-RestoreFrom` can reverse it:

- Disable USB selective suspend in the active power plan
- Turn off PCIe Link State Power Management
- Stop Windows powering down USB hubs/devices on the K7's path
- Clear selective suspend / idle power-down flags on the K7's device entries
- Remove disconnected (phantom) K7 and "Unknown USB Device" entries
- Disable Fast Startup
- Restart a K7 device that is present but failed, then trigger a hardware rescan

It never changes firmware, installs drivers, or touches Windows updates. Where a driver change would help (for example moving the K7 off the in-box UAC 1.0 driver), it tells you instead of doing it.

## Output

Each run writes a full transcript to `reports/FiiO-K7-Report-<timestamp>.txt`, and `-Fix` also writes `reports/FiiO-K7-Backup-<timestamp>.json`. The `reports` folder is git-ignored because it contains machine-specific details. If you contact FiiO support, attach the report (especially one from `-Watch`).

## Project layout

| File | Purpose |
| ------ | --------- |
| `Diagnose-FiiOK7.ps1` | The diagnostic script |
| `.vscode/launch.json` | VS Code debug configurations for the three main modes |
| `cspell.json` | Spell-checker dictionary for technical terms |
| `.gitignore` | Keeps generated reports out of the repository |

## Notes and limitations

- Device IDs matched are FiiO's USB vendor ID `2972` and XMOS `20B1` (the K7's USB receiver chip, which a K7 in firmware-update mode may show).
- The known-issue KB list reflects Microsoft's status at the time of writing and will age as fixes ship.
- Some results are inconclusive by nature: if Windows logs nothing, the K7 may never have signalled a connection. Use `-Watch` to confirm.
- Run it at your own risk; fixes only change standard Windows power and device settings, and are reversible via the backup.
