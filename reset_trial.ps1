<#
  reset_trial.ps1 - Reset IDM 30-day trial to a fresh state on THIS machine.

  What it does (see AGENTS.md "Trial reset" for the full analysis):
    1. Kills all IDM processes.
    2. Deletes the three on-disk trial anchors:
         %AppData%\IDM, %AppData%\DMCache, %ProgramData%\IDM
    3. Deletes HKCU\Software\DownloadManager (whole tree) + HKCU\Software\Backup_IDM.
       The ConfigTime subkey carries a DENY ACE, so a SYSTEM helper resets the
       DACL (SeBackup/SeRestore/SeSecurity/SeTakeOwnership) before RegDeleteTree.
    4. Optionally relaunches IDM (-Launch) so it writes a fresh 30-day trial.

  IMPORTANT
    - Run from an elevated PowerShell (the script self-elevates via UAC if needed).
    - This DELETES download history + settings. Use -Backup first, then restore
      with strip_reg.py (drops tvfrdt/radxcnt/LstCheck/LastCheckQU/ConfigTime).
    - NEVER set any anchor (folder time / ConfigTime) to a FUTURE date: IDM treats
      now < anchor as clock-tampering and writes a persistent "expired/blocked"
      state keyed by MachineGuid that survives reinstall. Full-wipe is the only
      known recovery.

  Usage:
    powershell -ExecutionPolicy Bypass -File reset_trial.ps1 [-Launch] [-Backup]
#>
param(
  [switch]$Launch,
  [switch]$Backup,
  [switch]$Keep    # backup, wipe, then restore download list + settings (strips trial anchors). Implies -Backup.
)

if ($Keep) { $Backup = $true }

$ErrorActionPreference = 'Stop'

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
  Write-Host "Elevating..."
  $argl = @('-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
  if ($Launch) { $argl += '-Launch' }
  if ($Backup) { $argl += '-Backup' }
  if ($Keep)   { $argl += '-Keep' }
  Start-Process powershell -Verb RunAs -ArgumentList $argl
  return
}

$sid   = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$idmDir = Join-Path $env:APPDATA 'IDM'
$dmCache = Join-Path $env:APPDATA 'DMCache'
$pdDir  = Join-Path $env:ProgramData 'IDM'
$idmExe = "$env:ProgramFiles(x86)\Internet Download Manager\IDMan.exe"
if (-not (Test-Path $idmExe)) {
  $idmExe = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
}

Write-Host "User SID: $sid"

# 1) kill IDM processes
foreach ($n in @('IDMan','IDMGrHlp','IEMonitor','IDMIETCC','IDMBroker','IDMMsgHost')) {
  Start-Process taskkill -ArgumentList "/F","/IM","$n.exe","/T" -Wait -NoNewWindow `
    -ErrorAction SilentlyContinue 2>$null
}
Start-Sleep -Milliseconds 500

# optional backup before wipe (-Keep forces a backup so it can restore afterwards)
$bk = $null
if ($Backup -or $Keep) {
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $bk = Join-Path $env:TEMP "idm_reset_backup_$stamp"
  New-Item -ItemType Directory -Path $bk -Force | Out-Null
  & reg export "HKCU\Software\DownloadManager" "$bk\DownloadManager.reg" /y 2>$null | Out-Null
  foreach ($d in @($idmDir,$dmCache,$pdDir)) {
    if (Test-Path $d) {
      $name = 'FILES_' + ($d -replace '[:\\]','_')
      Copy-Item -LiteralPath $d -Destination (Join-Path $bk $name) -Recurse -Force `
        -ErrorAction SilentlyContinue
    }
  }
  Write-Host "Backup: $bk"
}

# 2) delete on-disk anchors
foreach ($d in @($idmDir,$dmCache,$pdDir)) {
  if (Test-Path $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host ("deleted {0}: {1}" -f $d, (-not (Test-Path $d)))
}

# 3) delete registry. Try plain delete first; ConfigTime DENY needs the SYSTEM helper.
& reg delete "HKCU\Software\DownloadManager" /f 2>$null | Out-Null
& reg delete "HKCU\Software\Backup_IDM" /f 2>$null | Out-Null

$dmGone = -not (Test-Path "HKCU:\Software\DownloadManager")
if (-not $dmGone) {
  Write-Host "ConfigTime DENY blocked plain delete; running SYSTEM helper..."
  $helper = Join-Path $env:TEMP 'idm_reset_sys.ps1'
  $helperBody = @"
`$ErrorActionPreference='Continue'
`$sid='$sid'
`$sig=@'
using System;
using System.Runtime.InteropServices;
public class RegRst {
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern int RegOpenKeyEx(IntPtr h,string s,int o,int sam,out IntPtr r);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern int RegDeleteTree(IntPtr h,string s);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern int RegDeleteKey(IntPtr h,string s);
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
Add-Type -TypeDefinition `$sig
foreach(`$p in @('SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeSecurityPrivilege')){ [RegRst]::EnablePriv(`$p) }
`$HKU=[IntPtr]::new(0x80000003)
`$dm="`$sid`_dummy"  # placeholder replaced below
`$dm="`$sid`\Software\DownloadManager"
`$cfg="`$dm\ConfigTime"
[RegRst]::SetSD(`$HKU,`$dm,"O:BA",1)
[RegRst]::SetSD(`$HKU,`$dm,"D:PAI(A;;KA;;;WD)(A;;KA;;;BA)(A;;KA;;;SY)",4)
[RegRst]::SetSD(`$HKU,`$cfg,"O:BA",1)
[RegRst]::SetSD(`$HKU,`$cfg,"D:PAI(A;;KA;;;WD)(A;;KA;;;BA)(A;;KA;;;SY)",4)
`$hs=[IntPtr]::Zero
if([RegRst]::RegOpenKeyEx(`$HKU,"`$sid`\Software",0x04,0x000F003F,[ref]`$hs) -eq 0){
  [RegRst]::DelTree(`$hs,'DownloadManager') | Out-Null
  [RegRst]::DelTree(`$hs,'Backup_IDM') | Out-Null
  [RegRst]::RegCloseKey(`$hs) | Out-Null
}
`$rc=[RegRst]::Open(`$HKU,`$dm)
Set-Content -LiteralPath "`$env:TEMP\idm_reset_sys.result" -Value "verify_rc=`$rc"
"@
  Set-Content -LiteralPath $helper -Value $helperBody -Encoding UTF8
  $tn = 'IDMTrialReset'
  $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  & schtasks /Create /TN $tn /TR "$ps -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$helper`"" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F | Out-Null
  & schtasks /Run /TN $tn | Out-Null
  Start-Sleep -Seconds 6
  & schtasks /Delete /TN $tn /F 2>$null | Out-Null
  $res = Get-Content -LiteralPath "$env:TEMP\idm_reset_sys.result" -ErrorAction SilentlyContinue
  Write-Host "SYSTEM helper: $res"
  Remove-Item -LiteralPath $helper,"$env:TEMP\idm_reset_sys.result" -Force -ErrorAction SilentlyContinue
}

$dmGone = -not (Test-Path "HKCU:\Software\DownloadManager")
Write-Host "DownloadManager gone: $dmGone"

# 3b) RESTORE download list + settings (stripped of trial anchors) when -Keep
if ($Keep -and $bk) {
  $regBak = Join-Path $bk 'DownloadManager.reg'
  if (Test-Path $regBak) {
    $cleanReg = Join-Path $bk 'DownloadManager_clean.reg'
    $dropVals = @('tvfrdt','radxcnt','lstcheck','lastcheckqu')   # lower-case
    $lines = Get-Content -LiteralPath $regBak -Encoding Unicode
    $out = New-Object System.Collections.Generic.List[string]
    $skipBlock = $false; $i = 0
    while ($i -lt $lines.Count) {
      $ln = $lines[$i]; $s = $ln.Trim()
      if ($s.StartsWith('[') -and $s.EndsWith(']')) {
        $key = $s.Substring(1, $s.Length-2)
        $skipBlock = $key.EndsWith('\ConfigTime')
        if (-not $skipBlock) { $out.Add($ln) }
        $i++; continue
      }
      if ($skipBlock) { $i++; continue }
      if ($s.StartsWith('"') -and $s.Contains('"=')) {
        $vn = $s.Substring(1, $s.IndexOf('"',1)-1)
        if ($dropVals -contains $vn.ToLower()) {
          while ($s.EndsWith('\')) { $i++; $s = $lines[$i].Trim() }
          $i++; continue
        }
      }
      $out.Add($ln); $i++
    }
    Set-Content -LiteralPath $cleanReg -Value $out -Encoding Unicode
    & reg import $cleanReg 2>$null | Out-Null
    Write-Host "Restored registry (trial anchors stripped): $cleanReg"
  }
  # copy back download data; do NOT restore old folder CreationTime
  $bkFiles = Join-Path $bk ('FILES_' + ($idmDir -replace '[:\\]','_'))
  if (Test-Path $bkFiles) {
    if (-not (Test-Path $idmDir)) { New-Item -ItemType Directory -Path $idmDir -Force | Out-Null }
    foreach ($sub in @('DwnlData','Grabber','Scheduler')) {
      $src = Join-Path $bkFiles $sub
      if (Test-Path $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $idmDir $sub) -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Get-ChildItem -LiteralPath $bkFiles -Filter *.dat -File -ErrorAction SilentlyContinue | ForEach-Object {
      Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $idmDir $_.Name) -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Restored download data (DwnlData/Grabber/Scheduler/*.dat)"
  }
}

# 4) relaunch
if ($Launch -and (Test-Path $idmExe)) {
  Start-Process $idmExe
  Write-Host "IDM launched. Trial should read ~30 days."
}

Write-Host "Done. If a 'X days left / register now?' nag appears, that is normal trial behaviour."
