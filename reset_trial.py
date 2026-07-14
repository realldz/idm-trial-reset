#!/usr/bin/env python3
r"""reset_trial.py - Reset IDM 30-day trial to a fresh state on THIS machine.

Python port of reset_trial.ps1. See AGENTS.md "Trial reset" for the analysis.

What it does:
  1. Kills all IDM processes.
  2. Deletes the three on-disk trial anchors:
       %AppData%\IDM, %AppData%\DMCache, %ProgramData%\IDM
  3. Deletes HKCU\Software\DownloadManager (whole tree) + HKCU\Software\Backup_IDM.
     The ConfigTime subkey carries a DENY ACE, so a SYSTEM helper (scheduled task)
     resets the DACL before RegDeleteTree.
  4. Optionally relaunches IDM (--launch) so it writes a fresh 30-day trial.

IMPORTANT
  - Self-elevates via UAC if not already Administrator.
  - Plain reset DELETES download history + settings. Use --keep to back up, wipe,
    then restore the download list + settings with trial anchors stripped
    (tvfrdt/radxcnt/LstCheck/LastCheckQU/ConfigTime).
  - NEVER set any anchor (folder time / ConfigTime) to a FUTURE date: IDM treats
    now < anchor as clock-tampering and writes a persistent "expired/blocked"
    state keyed by MachineGuid that survives reinstall. Full-wipe is the only
    known recovery.

Usage:
    python reset_trial.py [--launch] [--backup] [--keep]
"""

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

IDM_PROCS = ("IDMan", "IDMGrHlp", "IEMonitor", "IDMIETCC", "IDMBroker", "IDMMsgHost")
DROP_VALS = ("tvfrdt", "radxcnt", "lstcheck", "lastcheckqu")  # lower-case
RESTORE_SUBDIRS = ("DwnlData", "Grabber", "Scheduler")


def _pf86() -> str:
    return os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")


def paths() -> dict:
    return {
        "idm": Path(os.environ["APPDATA"]) / "IDM",
        "dmcache": Path(os.environ["APPDATA"]) / "DMCache",
        "pd": Path(os.environ["ProgramData"]) / "IDM",
        "exe": Path(_pf86()) / "Internet Download Manager" / "IDMan.exe",
    }


# ── elevation ────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate(argv: list[str]) -> None:
    params = " ".join(f'"{a}"' for a in argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


def current_sid() -> str:
    out = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    # "DOMAIN\user","S-1-5-21-..."
    parts = [p.strip().strip('"') for p in out.split(",")]
    return parts[-1] if parts else ""


# ── steps ────────────────────────────────────────────────────────────

def kill_idm(log) -> None:
    for name in IDM_PROCS:
        subprocess.run(
            ["taskkill", "/F", "/IM", f"{name}.exe", "/T"],
            capture_output=True, timeout=15,
        )
    time.sleep(0.5)
    log("Killed IDM processes.")


def backup(p: dict, log) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bk = Path(os.environ["TEMP"]) / f"idm_reset_backup_{stamp}"
    bk.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["reg", "export", r"HKCU\Software\DownloadManager", str(bk / "DownloadManager.reg"), "/y"],
        capture_output=True, timeout=30,
    )
    for key in ("idm", "dmcache", "pd"):
        d = p[key]
        if d.exists():
            name = "FILES_" + str(d).replace(":", "_").replace("\\", "_")
            shutil.copytree(d, bk / name, dirs_exist_ok=True)
    log(f"Backup: {bk}")
    return bk


def wipe_folders(p: dict, log) -> None:
    for key in ("idm", "dmcache", "pd"):
        d = p[key]
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        log(f"deleted {d}: {not d.exists()}")


def _reg_gone() -> bool:
    r = subprocess.run(
        ["reg", "query", r"HKCU\Software\DownloadManager"],
        capture_output=True, timeout=10,
    )
    return r.returncode != 0


def _system_helper(sid: str, log) -> None:
    """DENY-ACE ConfigTime blocks plain delete; reset DACL + RegDeleteTree as SYSTEM."""
    helper = Path(os.environ["TEMP"]) / "idm_reset_sys.ps1"
    result = Path(os.environ["TEMP"]) / "idm_reset_sys.result"
    body = _HELPER_BODY.replace("__SID__", sid)
    helper.write_text(body, encoding="utf-8")
    tn = "IDMTrialReset"
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    subprocess.run(
        ["schtasks", "/Create", "/TN", tn, "/TR",
         f'{ps} -ExecutionPolicy Bypass -WindowStyle Hidden -File "{helper}"',
         "/SC", "ONCE", "/ST", "00:00", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"],
        capture_output=True, timeout=30,
    )
    subprocess.run(["schtasks", "/Run", "/TN", tn], capture_output=True, timeout=30)
    time.sleep(6)
    subprocess.run(["schtasks", "/Delete", "/TN", tn, "/F"], capture_output=True, timeout=30)
    res = result.read_text(encoding="utf-8", errors="ignore").strip() if result.exists() else "(no result)"
    log(f"SYSTEM helper: {res}")
    for f in (helper, result):
        try:
            f.unlink()
        except OSError:
            pass


def wipe_registry(sid: str, log) -> bool:
    subprocess.run(["reg", "delete", r"HKCU\Software\DownloadManager", "/f"], capture_output=True, timeout=15)
    subprocess.run(["reg", "delete", r"HKCU\Software\Backup_IDM", "/f"], capture_output=True, timeout=15)
    if not _reg_gone():
        log("ConfigTime DENY blocked plain delete; running SYSTEM helper...")
        _system_helper(sid, log)
    gone = _reg_gone()
    log(f"DownloadManager gone: {gone}")
    return gone


def _strip_reg(src: Path, dst: Path) -> None:
    """Drop trial anchor values + ConfigTime subkey block from an exported .reg."""
    lines = src.read_text(encoding="utf-16").splitlines()
    out: list[str] = []
    skip_block = False
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            key = s[1:-1]
            skip_block = key.endswith("\\ConfigTime")
            if not skip_block:
                out.append(ln)
            i += 1
            continue
        if skip_block:
            i += 1
            continue
        if s.startswith('"') and '"=' in s:
            vn = s[1:s.index('"', 1)]
            if vn.lower() in DROP_VALS:
                while s.endswith("\\"):
                    i += 1
                    s = lines[i].strip()
                i += 1
                continue
        out.append(ln)
        i += 1
    dst.write_text("\r\n".join(out), encoding="utf-16")


def restore(bk: Path, p: dict, log) -> None:
    reg_bak = bk / "DownloadManager.reg"
    if reg_bak.exists():
        clean = bk / "DownloadManager_clean.reg"
        _strip_reg(reg_bak, clean)
        subprocess.run(["reg", "import", str(clean)], capture_output=True, timeout=30)
        log(f"Restored registry (trial anchors stripped): {clean}")
    idm_dir = p["idm"]
    bk_files = bk / ("FILES_" + str(idm_dir).replace(":", "_").replace("\\", "_"))
    if bk_files.exists():
        idm_dir.mkdir(parents=True, exist_ok=True)
        for sub in RESTORE_SUBDIRS:
            src = bk_files / sub
            if src.exists():
                shutil.copytree(src, idm_dir / sub, dirs_exist_ok=True)
        for dat in bk_files.glob("*.dat"):
            shutil.copy2(dat, idm_dir / dat.name)
        log("Restored download data (DwnlData/Grabber/Scheduler/*.dat)")


def launch(p: dict, log) -> None:
    exe = p["exe"]
    if exe.exists():
        subprocess.Popen([str(exe)])
        log("IDM launched. Trial should read ~30 days.")


# ── orchestrator ─────────────────────────────────────────────────────

def run_reset(do_launch: bool, do_backup: bool, do_keep: bool, log=print) -> None:
    if do_keep:
        do_backup = True
    p = paths()
    sid = current_sid()
    log(f"User SID: {sid}")

    kill_idm(log)

    bk = None
    if do_backup:
        bk = backup(p, log)

    wipe_folders(p, log)
    wipe_registry(sid, log)

    if do_keep and bk:
        restore(bk, p, log)

    if do_launch:
        launch(p, log)

    log("Done. If a 'X days left / register now?' nag appears, that is normal trial behaviour.")


# SYSTEM helper: resets DACL on DownloadManager+ConfigTime, then RegDeleteTree.
# __SID__ is substituted at runtime. Pack=4 LUID split is mandatory (see AGENTS.md).
_HELPER_BODY = r"""
$ErrorActionPreference='Continue'
$sid='__SID__'
$sig=@'
using System;
using System.Runtime.InteropServices;
public class RegRst {
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern int RegOpenKeyEx(IntPtr h,string s,int o,int sam,out IntPtr r);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern int RegDeleteTree(IntPtr h,string s);
  [DllImport("advapi32.dll",SetLastError=true)] public static extern int RegCloseKey(IntPtr h);
  [DllImport("advapi32.dll",SetLastError=true)] public static extern int RegSetKeySecurity(IntPtr h,int si,byte[] sd);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,int rev,out IntPtr psd,out int sz);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,int a,out IntPtr t);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValue(string s,string n,out long l);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TP np,int len,IntPtr pv,IntPtr rl);
  [StructLayout(LayoutKind.Sequential,Pack=4)] struct TP { public int count; public uint luidLow; public int luidHigh; public int attr; }
  public static void EnablePriv(string name){
    IntPtr tok; OpenProcessToken(GetCurrentProcess(),0x28,out tok);
    long luid; LookupPrivilegeValue(null,name,out luid);
    TP tp=new TP(); tp.count=1; tp.luidLow=(uint)(luid & 0xFFFFFFFF); tp.luidHigh=(int)(luid>>32); tp.attr=2;
    AdjustTokenPrivileges(tok,false,ref tp,0,IntPtr.Zero,IntPtr.Zero);
  }
  public static void SetSD(IntPtr root,string sub,string sddl,int si){
    IntPtr h; if(RegOpenKeyEx(root,sub,0x04,0x000C0000,out h)!=0) return;
    IntPtr psd; int sz;
    if(ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out psd,out sz)){
      byte[] sd=new byte[sz]; Marshal.Copy(psd,sd,0,sz); LocalFree(psd);
      RegSetKeySecurity(h,si,sd);
    }
    RegCloseKey(h);
  }
  public static int DelTree(IntPtr root,string sub){ return RegDeleteTree(root,sub); }
  public static int Open(IntPtr root,string sub){ IntPtr h; int rc=RegOpenKeyEx(root,sub,0x04,0x20019,out h); if(rc==0)RegCloseKey(h); return rc; }
}
'@
Add-Type -TypeDefinition $sig
foreach($p in @('SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeSecurityPrivilege')){ [RegRst]::EnablePriv($p) }
$HKU=[IntPtr]::new(0x80000003)
$dm="$sid\Software\DownloadManager"
$cfg="$dm\ConfigTime"
[RegRst]::SetSD($HKU,$dm,"O:BA",1)
[RegRst]::SetSD($HKU,$dm,"D:PAI(A;;KA;;;WD)(A;;KA;;;BA)(A;;KA;;;SY)",4)
[RegRst]::SetSD($HKU,$cfg,"O:BA",1)
[RegRst]::SetSD($HKU,$cfg,"D:PAI(A;;KA;;;WD)(A;;KA;;;BA)(A;;KA;;;SY)",4)
$hs=[IntPtr]::Zero
if([RegRst]::RegOpenKeyEx($HKU,"$sid\Software",0x04,0x000F003F,[ref]$hs) -eq 0){
  [RegRst]::DelTree($hs,'DownloadManager') | Out-Null
  [RegRst]::DelTree($hs,'Backup_IDM') | Out-Null
  [RegRst]::RegCloseKey($hs) | Out-Null
}
$rc=[RegRst]::Open($HKU,$dm)
Set-Content -LiteralPath "$env:TEMP\idm_reset_sys.result" -Value "verify_rc=$rc"
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="Reset IDM 30-day trial on this machine.")
    ap.add_argument("--launch", action="store_true", help="relaunch IDM after wipe (writes fresh trial)")
    ap.add_argument("--backup", action="store_true", help="back up registry + data folders before wipe")
    ap.add_argument("--keep", action="store_true", help="backup, wipe, then restore download list + settings (implies --backup)")
    ap.add_argument("--pause", action="store_true", help="wait for a keypress before exiting (used by GUI-launched console)")
    args = ap.parse_args()

    if not is_admin():
        print("Elevating...")
        argv = [os.path.abspath(__file__)]
        for flag in ("launch", "backup", "keep"):
            if getattr(args, flag):
                argv.append(f"--{flag}")
        argv.append("--pause")
        elevate(argv)
        return

    try:
        run_reset(args.launch, args.backup, args.keep)
    finally:
        if args.pause:
            try:
                input("\nPress Enter to close...")
            except EOFError:
                pass


if __name__ == "__main__":
    main()
