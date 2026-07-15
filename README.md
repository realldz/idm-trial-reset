# idm-trial-reset

Reset the Internet Download Manager (IDM) 30-day trial to a fresh state on the
current machine. IDM anchors its trial redundantly across on-disk folders and
registry stores; wiping them all makes IDM treat the machine as a new install
and grant a fresh 30-day trial. An optional `--keep` mode preserves your
download list and settings.

Works fully offline — the trial verdict is local (no server check-in).

## Requirements

- Windows
- Python 3.9+ (for the Python CLI/GUI). The PowerShell script needs no Python.
- Administrator rights (all entry points self-elevate via UAC).

## Usage

### Python CLI (preferred)

```powershell
python reset_trial.py --keep --launch
```

Flags:

| Flag | Effect |
|------|--------|
| `--launch` | Relaunch IDM after the wipe (it writes the fresh 30-day trial). |
| `--backup` | Export registry + copy data folders to `%TEMP%\idm_reset_backup_<stamp>` before wiping. |
| `--keep`   | Backup, wipe, then **restore** the download list + settings with the trial anchors stripped. Implies `--backup`. |

`--keep` is the usual choice: it keeps your download history and settings while
granting a fresh trial. With no flags the script does a full clean wipe (you
lose download history and settings).

### GUI

```powershell
python reset_trial_gui.py
```

Checkboxes for *Keep download list + settings* and *Relaunch IDM*, plus a live
log pane.

### PowerShell (no Python required)

```powershell
powershell -ExecutionPolicy Bypass -File reset_trial.ps1 -Keep -Launch
```

`-Launch` / `-Backup` / `-Keep` mirror the Python flags.

## What it does

1. Kills all IDM processes (`IDMan`, `IDMGrHlp`, `IEMonitor`, `IDMIETCC`, `IDMBroker`, `IDMMsgHost`).
2. Deletes the on-disk trial anchors:
   - `%AppData%\IDM`
   - `%AppData%\DMCache`
   - `%ProgramData%\IDM`
3. Scans `HKCU\Software\Classes\Wow6432Node\CLSID` for IDM-related CLSID keys
   (IAS-style pattern: GUIDs with digit-default, MData/Model/scansk/Therad values,
   empty keys, or digit-in-Version) and deletes them.
4. Deletes `HKCU\Software\DownloadManager` (whole tree) and `HKCU\Software\Backup_IDM`.
   The `ConfigTime` subkey carries a DENY ACE, so a **SYSTEM** helper (scheduled
   task) resets the DACL before `RegDeleteTree`.
5. With `--keep`, restores the download list + settings from the backup, stripped
   of the trial anchor values (`tvfrdt`, `radxcnt`, `LstCheck`, `LastCheckQU`,
   `ConfigTime`), and copies back `DwnlData` / `Grabber` / `Scheduler` / `*.dat`.
6. With `--launch`, relaunches IDM.

## Warning: never future-date the anchors

Do **not** try to fake a long trial by setting any anchor (folder creation time
or the `ConfigTime` value) to a future date. IDM treats `now < anchor` as clock
tampering and writes a persistent "expired/blocked" state keyed by the machine
GUID that survives an ordinary wipe and reinstall. A full SYSTEM-level wipe is
the only known recovery.

## Manual steps (if the scripts are unavailable)

1. Kill IDM: `taskkill /F /IM IDMan.exe /T` (elevated).
2. Delete `%AppData%\IDM`, `%AppData%\DMCache`, `%ProgramData%\IDM`.
3. As SYSTEM (`schtasks /RU SYSTEM /RL HIGHEST` — needed because `ConfigTime` has
   a DENY ACE): enable SeBackup/SeRestore/SeSecurity, reset the DACL on
   `DownloadManager` + `ConfigTime` via `RegSetKeySecurity`
   (SDDL `O:BA` + `D:PAI(A;;KA;;;WD)(A;;KA;;;BA)(A;;KA;;;SY)`), then
   `RegDeleteTree` both `HKCU\Software\DownloadManager` and `HKCU\Software\Backup_IDM`.
4. Launch IDM → fresh 30-day trial. The first "X days left / register now?"
   popup is the normal trial nag, not an error.

## Disclaimer

For educational and personal use. Resetting a trial to avoid purchasing a
license may violate IDM's EULA. Buy a license if you use IDM long-term.
