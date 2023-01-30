# Purpose: install malware reverse tools on a Windows 10 VM
# by Renato Marinho

If (-not (Test-Path "C:\ProgramData\chocolatey")) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey"
  Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Chocolatey is already installed."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing utilities..."
choco install -y --limit-output --no-progress NotepadPlusPlus WinRar processhacker

# This repo often causes failures due to incorrect checksums, so we ignore them for Chrome
choco install -y --limit-output --no-progress --ignore-checksums GoogleChrome 

# Instalando Word 
#Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Word and Excel..."
#choco install -y --limit-output --no-progress --ignore-checksums microsoft-office-deployment /product WordRetail, ExcelRetail

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Utilties installation complete!"


# Purpose: Install additional packages from Chocolatey.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing additional Choco packages..."


Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey extras..."
choco install -y --limit-output --no-progress wireshark winpcap apimonitor die explorersuite 7zip graphviz hxd python3 dnspy

choco install -y --limit-output --no-progress --ignore-checksums pestudio

# Creating pestudio shortcut
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\pestudio.lnk")
$ShortCut.TargetPath="C:\ProgramData\chocolatey\bin\pestudio.exe"
$ShortCut.WorkingDirectory = "C:\ProgramData\chocolatey\bin\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\ProgramData\chocolatey\bin\pestudio.exe, 0";
$ShortCut.Save()

# Creating apimonitor shortcut
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\apimonitor-x64.lnk")
$ShortCut.TargetPath="C:\ProgramData\chocolatey\bin\apimonitor-x64.exe"
$ShortCut.WorkingDirectory = "C:\ProgramData\chocolatey\bin\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\ProgramData\chocolatey\bin\apimonitor-x64.exe, 0";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\apimonitor-x86.lnk")
$ShortCut.TargetPath="C:\ProgramData\chocolatey\bin\apimonitor-x86.exe"
$ShortCut.WorkingDirectory = "C:\ProgramData\chocolatey\bin\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\ProgramData\chocolatey\bin\apimonitor-x86.exe, 0";
$ShortCut.Save()

# Creating die shortcut
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\die.lnk")
$ShortCut.TargetPath="C:\ProgramData\chocolatey\bin\die.exe"
$ShortCut.WorkingDirectory = "C:\ProgramData\chocolatey\bin\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\ProgramData\chocolatey\bin\die.exe, 0";
$ShortCut.Save()

# Creating explorersuite shortcut
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\CFF Explorer.lnk")
$ShortCut.TargetPath="C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe"
$ShortCut.WorkingDirectory = "C:\Program Files\NTCore\Explorer Suite\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe, 0";
$ShortCut.Save()

# Creating hxd shortcut
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\HxD.lnk")
$ShortCut.TargetPath="C:\Program Files\HxD\HxD.exe"
$ShortCut.WorkingDirectory = "C:\Program Files\HxD\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\Program Files\HxD\HxD.exe, 0";
$ShortCut.Save()

# Creating dnspy shortcut
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\dnSpy.lnk")
$ShortCut.TargetPath="C:\ProgramData\chocolatey\bin\dnSpy.exe"
$ShortCut.WorkingDirectory = "C:\ProgramData\chocolatey\bin\";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "C:\ProgramData\chocolatey\bin\dnSpy.exe, 0";
$ShortCut.Save()

# Instalando modulos do Python
$env:Path += ";c:\python311\scripts\;c:\python311\"
python.exe -m pip install --upgrade pip
pip install requests
pip install netstruct
pip install pefile

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Choco addons complete!"

# Installs a handful of SysInternals tools on the host into c:\Tools\Sysinternals
# Also installs Sysmon and Olaf Harton's Sysmon config

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing SysInternals Tooling..."
$sysinternalsDir = "C:\Tools\Sysinternals"
$sysmonDir = "C:\ProgramData\Sysmon"
If(!(test-path $sysinternalsDir)) {
  New-Item -ItemType Directory -Force -Path $sysinternalsDir
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Tools directory exists, no need to re-install. Exiting."
  exit
}

If(!(test-path $sysmonDir)) {
  New-Item -ItemType Directory -Force -Path $sysmonDir
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Sysmon directory exists, no need to re-install. Exiting."
  exit
}

$autorunsPath = "C:\Tools\Sysinternals\Autoruns64.exe"
$procmonPath = "C:\Tools\Sysinternals\Procmon.exe"
$psexecPath = "C:\Tools\Sysinternals\PsExec64.exe"
$procexpPath = "C:\Tools\Sysinternals\procexp64.exe"
$sysmonPath = "C:\Tools\Sysinternals\Sysmon64.exe"
$sdeletePath = "C:\Tools\Sysinternals\Sdelete64.exe"
$tcpviewPath = "C:\Tools\Sysinternals\Tcpview.exe"
$sysmonConfigPath = "$sysmonDir\sysmonConfig.xml"
#$shortcutLocation = "$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\"
$shortcutLocation = "$env:USERPROFILE\Desktop\"

$WScriptShell = New-Object -ComObject WScript.Shell

# Microsoft likes TLSv1.2 as well
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Autoruns64.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Autoruns64.exe', $autorunsPath) 
} Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/Autoruns64.exe', $autorunsPath) 
}
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "Autoruns.lnk")
$Shortcut.TargetPath = $autorunsPath
$Shortcut.Save()

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Procmon.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Procmon.exe', $procmonPath)
} Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/Procmon.exe', $procmonPath)
}
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "Process Monitor.lnk")
$Shortcut.TargetPath = $procmonPath
$Shortcut.Save()

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading PsExec64.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/PsExec64.exe', $psexecPath)
} Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/PsExec64.exe', $psexecPath)
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading procexp64.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/procexp64.exe', $procexpPath)
} Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/procexp64.exe', $procexpPath)
}
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "Process Explorer.lnk")
$Shortcut.TargetPath = $procexpPath
$Shortcut.Save()

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading sdelete64.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/sdelete64.exe', $sdeletePath)
}
Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/sdelete64.exe', $sdeletePath)
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Sysmon64.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon64.exe', $sysmonPath)
} Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/Sysmon64.exe', $sysmonPath)
}
Copy-Item $sysmonPath $sysmonDir

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Tcpview.exe..."
Try { 
  (New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Tcpview.exe', $tcpviewPath)
} Catch { 
  Write-Host "HTTPS connection failed. Switching to HTTP :("
  (New-Object System.Net.WebClient).DownloadFile('http://live.sysinternals.com/Tcpview.exe', $tcpviewPath)
}
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "Tcpview.lnk")
$Shortcut.TargetPath = $tcpviewPath
$Shortcut.Save()

# Restart Explorer so the taskbar shortcuts show up
if (Get-Process -ProcessName explorer -ErrorAction 'silentlycontinue') {
  Stop-Process -ProcessName explorer -Force
}

# Incluindo sysinternals no path
$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
$newpath = "$oldpath;C:\Tools\Sysinternals\"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Reverse Tooling..."
$reverseToolsDir = "C:\Tools\Reverse"

If(!(test-path $reverseToolsDir)) {
  New-Item -ItemType Directory -Force -Path $reverseToolsDir
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Tools directory exists, no need to re-install. Exiting."
  exit
}


# X64DBG
$x64dbgRoot = $reverseToolsDir + "\x64dbg\"

If(!(test-path $x64dbgRoot)) {
  New-Item -ItemType Directory -Force -Path $x64dbgRoot
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Tools directory exists, no need to re-install. Exiting."
  exit
}

$x64dbgZip = $reverseToolsDir + "\x64dbg\snapshot_2022-03-26_14-14.zip"
$x64dbgPath = $reverseToolsDir + "\x64dbg\release\x64\x64dbg.exe"
$x32dbgPath = $reverseToolsDir + "\x64dbg\release\x32\x32dbg.exe"

#$shortcutLocation = "$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\"
$shortcutLocation = "$env:USERPROFILE\Desktop\"

$WScriptShell = New-Object -ComObject WScript.Shell

# Microsoft likes TLSv1.2 as well
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading X64DBG ZIP..."

Invoke-WebRequest -UserAgent "Wget" -Uri "https://sourceforge.net/projects/x64dbg/files/snapshots/snapshot_2022-03-26_14-14.zip/download" -OutFile $x64dbgZip
Expand-Archive -path "$x64dbgZip" -destinationpath "$x64dbgRoot" -Force

$Shortcutx64dbg = $WScriptShell.CreateShortcut($ShortcutLocation + "x64dbg.lnk")
$Shortcutx64dbg.TargetPath = $x64dbgPath
$Shortcutx64dbg.Save()

$Shortcutx32dbg = $WScriptShell.CreateShortcut($ShortcutLocation + "x32dbg.lnk")
$Shortcutx32dbg.TargetPath = $x32dbgPath
$Shortcutx32dbg.Save()

# REGSHOT

$regshotRoot = $reverseToolsDir + "\regshot\"
$regshotbin = $regshotRoot + "\Regshot-x64-Unicode.exe"
$regshotzip = $regshotRoot + "\Regshot-1.9.0.7z"

If(!(test-path $regshotRoot)) {
  New-Item -ItemType Directory -Force -Path $regshotRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://sourceforge.net/projects/regshot/files/regshot/1.9.0/Regshot-1.9.0.7z/download" -OutFile $regshotzip

set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"
sz x  "$regshotzip" -o"$regshotRoot";

$Shortcutregshot = $WScriptShell.CreateShortcut($ShortcutLocation + "regshot.lnk")
$Shortcutregshot.TargetPath = $regshotbin
$Shortcutregshot.WorkingDirectory = $regshotRoot
$Shortcutregshot.Save()



# PROCDOT
$procdotRoot = $reverseToolsDir + "\procdot"
$procdotbin = $procdotRoot + "\win64\procdot.exe"
$procdotzip = $procdotRoot + "\procdot_1_21_56_windows.zip"

If(!(test-path $procdotRoot)) {
  New-Item -ItemType Directory -Force -Path $procdotRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://procdot.com/download/procdot/binaries/procdot_1_21_56_windows.zip" -OutFile $procdotzip

set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"
sz x  "$procdotzip" -o"$procdotRoot" -p"procdot";


$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "procdot.lnk")
$Shortcut.TargetPath = $procdotbin
$Shortcut.Save()


# WINDUMP
$windumpRoot = $reverseToolsDir + "\windump"
$windumpbin = $windumpRoot + "\WinDump.exe"

If(!(test-path $windumpRoot)) {
  New-Item -ItemType Directory -Force -Path $windumpRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe" -OutFile $windumpbin


# IDA FREE
$idaRoot = $reverseToolsDir + "\ida"
$idabin = $idaRoot + "\idafree77_windows.exe"

If(!(test-path $idaRoot)) {
  New-Item -ItemType Directory -Force -Path $idaRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://out7.hex-rays.com/files/idafree77_windows.exe" -OutFile $idabin

Start-Process $idabin -ArgumentList "--mode unattended"

# Bintext
$bintextRoot = $reverseToolsDir + "\bintext"
$bintextzip = $bintextRoot + "\bintext303.zip"
$bintextbin = $bintextRoot + "\bintext.exe"

If(!(test-path $bintextRoot)) {
  New-Item -ItemType Directory -Force -Path $bintextRoot

}

#Invoke-WebRequest -UserAgent "Wget" -Uri "http://b2b-download.mcafee.com/products/tools/foundstone/bintext303.zip" -OutFile $bintextzip
Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/mfput/McAfee-Tools/blob/master/bintext303.zip" -OutFile $bintextzip

Expand-Archive -path "$bintextzip" -destinationpath "$bintextRoot" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "bintext.lnk")
$Shortcut.TargetPath = $bintextbin
$Shortcut.Save()

# LECMD
$lecmdRoot = $reverseToolsDir + "\lecmd"
$lecmdzip = $lecmdRoot + "\LECmd.zip"
$lecmdbin = $lecmdRoot + "\LECmd.exe"

If(!(test-path $lecmdRoot)) {
  New-Item -ItemType Directory -Force -Path $lecmdRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://f001.backblazeb2.com/file/EricZimmermanTools/LECmd.zip" -OutFile $lecmdzip

Expand-Archive -path "$lecmdzip" -destinationpath "$lecmdRoot" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "LECmd.lnk")
$Shortcut.TargetPath = $lecmdbin
$Shortcut.Save()

# CAPA
$capaRoot = $reverseToolsDir + "\capa"
$capazip = $capaRoot + "\capa-v3.2.0-windows.zip"
$capabin = $capaRoot + "\capa.exe"

If(!(test-path $capaRoot)) {
  New-Item -ItemType Directory -Force -Path $capaRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/mandiant/capa/releases/download/v3.2.0/capa-v3.2.0-windows.zip" -OutFile $capazip

Expand-Archive -path "$capazip" -destinationpath "$capaRoot" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "CAPA.lnk")
$Shortcut.TargetPath = $capabin
$Shortcut.Save()

# SCDBG
$scdbgRoot = $reverseToolsDir + "\scdbg"
$scdbgzip = $scdbgRoot + "\scdbg.zip"
$scdbgbin = $scdbgRoot + "\gui_launcher.exe"

If(!(test-path $scdbgRoot)) {
  New-Item -ItemType Directory -Force -Path $scdbgRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "http://sandsprite.com/CodeStuff/scdbg.zip" -OutFile $scdbgzip

Expand-Archive -path "$scdbgzip" -destinationpath "$scdbgRoot" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "scdbg.lnk")
$Shortcut.TargetPath = $scdbgbin
$Shortcut.Save()

#NORIBEN
$noriRoot = $reverseToolsDir + "\noriben"
$norizip = $scdbgRoot + "\master.zip"

If(!(test-path $noriRoot)) {
  New-Item -ItemType Directory -Force -Path $scdbgRoot
  New-Item -ItemType Directory -Force -Path "c:\users\IEUser\Desktop\Noriben"
  New-Item -ItemType Directory -Force -Path "c:\users\IEUser\Desktop\Noriben\output"
  
}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/Rurik/Noriben/archive/refs/heads/master.zip" -OutFile $norizip

Expand-Archive -path "$norizip" -destinationpath "$noriRoot" -Force


$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "\Noriben\Noriben.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "/k c:\python311\python.exe `"C:\Tools\Reverse\noriben\noriben-master\Noriben.py`""
$Shortcut.WorkingDirectory = "C:\users\IEUser\Desktop\Noriben\output"
$Shortcut.Save()


# UPX
$upxRoot = $reverseToolsDir + "\upx"
$upxzip = $upxRoot + "\upx-3.96-win64.zip"

If(!(test-path $upxRoot)) {
  New-Item -ItemType Directory -Force -Path $upxRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/upx/upx/releases/download/v3.96/upx-3.96-win64.zip" -OutFile $upxzip

Expand-Archive -path "$upxzip" -destinationpath "$upxRoot" -Force



# COBALT STRIKE PARSER
$cobaltRoot = $reverseToolsDir + "\cobaltstrikeparser"
$cobaltzip = $cobaltRoot + "\master.zip"

If(!(test-path $cobaltRoot)) {
  New-Item -ItemType Directory -Force -Path $cobaltRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/Sentinel-One/CobaltStrikeParser/archive/refs/heads/master.zip" -OutFile $cobaltzip

Expand-Archive -path "$cobaltzip" -destinationpath "$cobaltRoot" -Force



# WINPCAP installer
$winpcapRoot = $reverseToolsDir + "\winpcap"
$winpcapzip = $winpcapRoot + "\WinPcap_4_1_3.exe"

If(!(test-path $winpcapRoot)) {
  New-Item -ItemType Directory -Force -Path $winpcapRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe" -OutFile $winpcapzip

#DNSpy 32bits
$dnspyRoot = $reverseToolsDir + "\dnspy32"
$dnspyzip = $dnspyRoot + "\dnSpy-net-win32.zip"
$dnspybin = $dnspyRoot + "\dnSpy.exe"

If(!(test-path $dnspyRoot)) {
  New-Item -ItemType Directory -Force -Path $dnspyRoot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win32.zip" -OutFile $dnspyzip

Expand-Archive -path "$dnspyzip" -destinationpath "$dnspyRoot" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "dnSpy32.lnk")
$Shortcut.TargetPath = $dnspybin
$Shortcut.Save()

#PEBear x86
$pebearx86Root = $reverseToolsDir + "\pebearx86"
$pebearx86zip = $pebearx86Root + "\PE-bear_0.5.5.3_x86_win_vs17.zip"
$pebearx86bin = $pebearx86Root + "\PE-Bear.exe"

If(!(test-path $pebearx86Root)) {
  New-Item -ItemType Directory -Force -Path $pebearx86Root

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/hasherezade/pe-bear-releases/releases/download/0.5.5.3/PE-bear_0.5.5.3_x86_win_vs17.zip" -OutFile $pebearx86zip

Expand-Archive -path "$pebearx86zip" -destinationpath "$pebearx86Root" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "PE-Bear-x86.lnk")
$Shortcut.TargetPath = $pebearx86bin
$Shortcut.Save()

# PEBear64
$pebear64Root = $reverseToolsDir + "\pebearx64"
$pebear64zip = $pebear64Root + "\PE-bear_0.5.5.3_x64_win_vs17.zip"
$pebear64bin = $pebear64Root + "\PE-Bear.exe"

If(!(test-path $pebear64Root)) {
  New-Item -ItemType Directory -Force -Path $pebear64Root

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/hasherezade/pe-bear-releases/releases/download/0.5.5.3/PE-bear_0.5.5.3_x64_win_vs17.zip" -OutFile $pebear64zip

Expand-Archive -path "$pebear64zip" -destinationpath "$pebear64Root" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "PE-Bear-x64.lnk")
$Shortcut.TargetPath = $pebear64bin
$Shortcut.Save()

# PDFStream-dumper (download)
$pdfstreamdumperroot = $reverseToolsDir + "\pdfstreamdumper"
$pdfstreamdumperzip = $pdfstreamdumperroot + "\PDFStreamDumper_Setup.exe"

If(!(test-path $pdfstreamdumperroot)) {
  New-Item -ItemType Directory -Force -Path $pdfstreamdumperroot

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/dzzie/pdfstreamdumper/releases/download/current/PDFStreamDumper_Setup.exe" -OutFile $pdfstreamdumperzip

# HollowsHunter
$hollowshunter64Root = $reverseToolsDir + "\hollowshunter64"
$hollowshunter64zip = $hollowshunter64Root + "\hollows_hunter64.zip"
$hollowshunter64bin = $hollowshunter64Root + "\hollows_hunter.exe"

If(!(test-path $hollowshunter64Root)) {
  New-Item -ItemType Directory -Force -Path $hollowshunter64Root

}

Invoke-WebRequest -UserAgent "Wget" -Uri "https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.4/hollows_hunter64.zip" -OutFile $hollowshunter64zip

Expand-Archive -path "$hollowshunter64zip" -destinationpath "$hollowshunter64Root" -Force

$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation + "HollowsHunter-x64.lnk")
$Shortcut.TargetPath = $hollowshunter64bin
$Shortcut.Save()



# Incluindo diretorios no path
$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
$newpath = "$oldpath;" + $upxRoot + "\upx-3.96-win64\;" + $capaRoot + "\;" + $lecmdRoot + "\;"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath

# Instrucoes para desativacao do Windows Defender

# Script baseado em https://raw.githubusercontent.com/TairikuOokami/Windows/main/Microsoft%20Defender%20Disable.bat:

$disableDefBat = @'
rem 1 - Disable Real-time protection
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

rem 0 - Disable Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f

rem Disable Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

rem Disable systray icon
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f

rem Remove context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f

rem Disable services (it will stop WdFilter.sys as well, better not to disable the driver by itself)
rem reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

shutdown /r
'@

New-Item -ItemType Directory -Force -Path "c:\users\IEUser\Desktop\DisableDefender\"

$disableDefBat | Out-File -Encoding ASCII 'c:\users\IEUser\Desktop\DisableDefender\disable-defender.bat'

$disableDefReadme = @'

DISABLING WINDOWS DEFENDER

1. Disable Real Time Protection and Tampering Protection of Windows Defender at: 
	Start -> PC Settings -> Update and Security -> Windows Security -> Virus and Threat Protection -> Virus and Threat Protection Settings -> Manage Settings

2. Open a cmd prompt with Admin privileges and execute:
	> cd \users\IEUser\desktop\disabledefender
	> disable-defencer.bat

3. Reboot the VM and you should have the Windows Defender disabled.


'@

$disableDefReadme | Out-File 'c:\users\IEUser\Desktop\DisableDefender\README.txt'
