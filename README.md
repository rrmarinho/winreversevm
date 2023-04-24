# Win Reverse VM

The objective of this project is to make it easier to prepare a Windows 10 Virtual Machine for malware analysis. 

The project installs a curated list of reverse engeneering tools on a Windows 10 VM provided by Microsoft for an evaluation period.

# Installation

## Requirements (minimum)

80 GB disk space 

8GB RAM

## Installation Steps

### 1. Windows 10 VM:
<!--
https://mega.nz/#P!AgFaInMQClH1Q_y_8lCvRQKcneDOMpSKmCFhv6tJ47x3AH1OZMyGDcPchBsv7nrzxlbUg4h8HXJiXuZs9ePwqE5yV-MM-9VZM1F-BN6zngO7KSKes9CI03hRcSwtz5jFiVt7-LEa_XE
-->
Install a Windows 10 VM on your virtual machine environment. 

Remember to take a snapshot to have a fresh install version of your VM.

### 2. Install the tools:

  - Download the 'install.ps1' script to your VM;
  - Open a Powershell with Admin privileges;
  - Unblock the file using the command:
    - `Unblock-File .\install.ps1`
  - Disable Script Execution Policy:
    - `Set-ExecutionPolicy Unrestricted`
  - Execute the 'install.ps1' script:
    - `.\install.ps1`

  The install process may take more or less time depending on the internet link. In general, the average installation time is approximately 1 hour.
  
  OBS: if the screen below appears during the installation process, just click "Abort".
  
  ![image](https://user-images.githubusercontent.com/32780523/215539890-993c222a-7070-46f1-88e1-52d4ee614ba4.png)


### 3. Disable Windows Defender

  - Disable Real Time Protection and Tampering Protection (if available) of Windows Defender at:
  
    	Start -> PC Settings -> Update and Security -> Windows Security -> Virus and Threat Protection -> Virus and Threat Protection Settings -> Manage Settings
  
  - Open a cmd prompt with Admin privileges and execute:
  
      - `cd \users\IEUser\desktop\disabledefender`
      - `.\disable-defender.bat`
     
  Reboot the VM and you should have the Windows Defender disabled.


A screenshot of the Windows 10 VM after the installation.

![image](https://user-images.githubusercontent.com/32780523/184223861-2f73ef87-2597-4f6b-a955-bb57a553cfaf.png)


## Disclaimer

This download and configuration script is provided as is with the intent to help malware analysts to create a Windows 10 Lab. I take NO responsibility and/or liability for how you choose to use it. 

Additionally, you as a user of this script must review, accept and comply with the license
terms of each downloaded/installed packages.


  

