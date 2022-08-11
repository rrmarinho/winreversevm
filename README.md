# Win Reverse VM

The objective of this project is to make it easy for malware analysts to prepare a Windows 10 Virtual Machine with analysis tools. 

# Installation

## Requirements

40 GB disk space (minimum)

2GB RAM

## Installation Steps

### 1. Download a Windows 10 VM from Microsoft:

https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/

On the VM Download website, choose:

  Virtual Machines: MSEdge on Windows 10 (x64) Stable 1809
  Choose a VM Platform: VMWare (Windows, Mac)

After downloading the file, import the 'ovf' file using your VMWare software.

Remember to take a snapshot to have a fresh install version of your VM.

### 2. Install the tools:

  - Download the 'install.ps1' script to your VM;
  - Open a Powershell with Admin privileges;
  - Unblock the file using the command:
    - `Unblock-FIle .\install.ps1`
  - Disable Script Execution Policy:
    - `Set-ExecutionPolicy Unrestricted`
  - Execute the 'install.ps1' script:
    - `.\install.ps1`

  The install process may take more or less time depending on the internet link. In general, the average installation time is approximately 1 hour.

### 3. Disable Windows Defender

  - Disable Real Time Protection and Tampering Protection of Windows Defender at:
    	Start -> PC Settings -> Update and Security -> Windows Security -> Virus and Threat Protection -> Virus and Threat Protection Settings -> Manage Settings
  - Open a cmd prompt with Admin privileges and execute:
      - `cd \users\IEUser\desktop\disabledefender`
      - `disable-defencer.bat`
     
  Reboot the VM and you should have the Windows Defender disabled.


A screenshot of the Windows 10 VM after the installation.


  

