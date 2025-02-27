<img width="400" src="https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Password.jpg" alt="Password Image"/>

# Threat Hunt Report: Credential Dumping
- [Scenario Creation](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Scenario-Creation.md)

  

## Platforms and Languages Leveraged
- Windows 10 Virtual Machine (king-vm)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- SIEM: Microsoft Sentinel
- Kusto Query Language (KQL)
- WebBrowserPassView.exe (Password Recovery Tool)

## Scenario

Microsoft Sentinel generated an alert indicating potential credential dumping via a password recovery tool. The impacted device is king-vm, with user king apparently downloading and executing WebBrowserPassView.exe. This tool extracted stored web browser credentials and saved them into Passwords.txt. Further investigation focused on whether these credentials were exfiltrated or otherwise misused.

![alt text](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Cred-Stuff-Incident-Alert.png)

### High-Level Credential Dumping IoC Discovery Plan
- **Check DeviceFileEvents** for any common credential file names such as Passwords.txt, Logins.txt, or Dumped_Credentials.txt.
- **Check DeviceNetworkEvents** for connections to hosting or file-sharing sites that might indicate exfiltration attempts.
- **Check for presence of known credential dumping tools** (e.g., WebBrowserPassView.exe).

---

## Steps Taken

### 1. Investigated File Creation – Identifying Dumped Credentials

Checked for files typically associated with credential dumping (e.g., Passwords.txt, logins.txt, dumped_credentials.txt).

**Query used to locate file creation:**

```kql
DeviceFileEvents
| where tolower(FileName) in (tolower("dumped_credentials.txt"), tolower("passwords.txt"), tolower("logins.txt"))
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath
```

![alt text](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Cred-Stuff1.png)

#### Findings:

- Detected Device: king-vm
- User: king
- File Path: C:\Users\king\Documents\Passwords.txt
- File Creation Time: 2025-02-27T17:22:44.3507344Z

---

### 2. Investigated the Source – Application Analysis
Observed WebBrowserPassView.exe in the logs, a known password recovery utility that extracts credentials from web browsers.

**Query used to locate file events around the creation time of Passwords.txt:**

```kql
DeviceFileEvents
| where DeviceName == "king-vm"
| where InitiatingProcessAccountName == "king"
| where TimeGenerated between (todatetime('2025-02-27T17:22:44.3507344Z') - 10m .. todatetime('2025-02-27T17:22:44.3507344Z') + 5m)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath
```

![alt text](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Cred-Stuff2.png)

#### Findings:

- Identified Application: WebBrowserPassView.exe
- File Location: C:\Users\king\Downloads\WebBrowserPassView.exe
- Execution Time: Shortly before Passwords.txt was created

---
### 3. Investigated the Download Source
Discovered that the user visited nirsoft.net (which hosts WebBrowserPassView.exe) using Microsoft Edge shortly before execution.

**Query used to locate related network events:**

```kql
DeviceNetworkEvents
| where DeviceName == "king-vm"
| where InitiatingProcessAccountName contains "king"
| where TimeGenerated between (todatetime('2025-02-27T17:22:44.3507344Z') - 10m .. todatetime('2025-02-27T17:22:44.3507344Z') + 5m)
| project TimeGenerated, ActionType, RemoteIP, RemoteUrl, InitiatingProcessParentFileName
```

![alt text](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Cred-Stuff3.png)

#### Findings:

Accessed Website: nirsoft.net
Browser Used: Microsoft Edge
Time of Access: Shortly before WebBrowserPassView.exe execution

---

### 4. Investigated Potential Exfiltration
No evidence was found of Passwords.txt being uploaded to external file-sharing or cloud storage services.

**Query used to check potential exfiltration:**

```kql
DeviceNetworkEvents
| where DeviceName == "king-vm"
| where RemoteUrl !contains "microsoft.com"  // Exclude trusted domains
| where RemoteUrl has_any ("file.io", "anonfiles.com", "pastebin.com", "mega.nz", "transfer.sh", "wetransfer.com", "sendspace.com", "gofile.io")
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "explorer.exe", "curl.exe", "python.exe", "wget.exe")
| where Protocol in ("HTTPS", "HTTP")
```

![alt text](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Cred-Stuff4.png)

#### Findings:

- No detected uploads to external sites
- Possible intent to move the file via USB rather than upload it


---

## Chronological Event Timeline


### 1. File Creation – Passwords.txt
Timestamp: 2025-02-27T17:22:44.3507344Z
Event: User king created the credentials file Passwords.txt.
File Path: C:\Users\king\Documents\Passwords.txt

### 2. Application Execution – WebBrowserPassView.exe
Timestamp: Shortly before Passwords.txt was generated
Event: User king ran WebBrowserPassView.exe, extracting stored web browser credentials.

### 3. Download from Nirsoft.net
Timestamp: Within ~10 minutes before credential file creation
Event: Nirsoft.net accessed via Microsoft Edge
Action: Download of WebBrowserPassView.exe flagged by SmartScreen but user bypassed

### 4. No Observed Exfiltration
Timestamp: Post-creation of Passwords.txt
Event: No network events indicate data transfer to external file-sharing platforms.


---
## Response Taken

### Following detection of unauthorized credential dumping:

- Isolated the VM (king-vm) via Microsoft Defender for Endpoint (MDE) to prevent further spread or potential exfiltration.
- Ran a full antivirus scan to detect any residual threats or malicious executables.
- Collected an Investigation Package for forensic analysis, ensuring logs and artifacts are preserved.

  ![alt text](https://github.com/K-ING-TECH/Incident-Response_Credential-Dumping/blob/main/Cred-Stuff-Triage.png)

---
## Lessons Learned & Future Recommendations:

- Restrict Execution of Credential Recovery Tools: Enforce Application Control to block tools like WebBrowserPassView.exe.
- User Education: Train users on risks of downloading unapproved software.
- Monitor for Suspicious File Creation Patterns: Update Sentinel alerts to flag credentials-related filenames in user directories.
- Incident Response Plan: Mitigation & Prevention:
- USB Restrictions: Implement device control policies to limit transferring of sensitive files.
- ASR Rule Enforcement: Block execution of known credential dumping software via Defender Attack Surface Reduction.
- SmartScreen Policy: Enforce stricter SmartScreen checks so users cannot bypass warnings easily.

---
## MITRE ATT&CK TTPs
- **Credential Access (TA0006) – T1003 (Credential Dumping):** Use of WebBrowserPassView.exe to obtain stored credentials.
- **Initial Access (TA0001) – T1078 (Valid Accounts):** User king leveraged their own account to execute the tool.
- **Execution (TA0002) – T1204.002 (User Execution: Malicious File):** Downloaded and launched a password recovery tool.
- **Persistence (TA0003) – T1547.001 (Boot or Logon Autostart Execution):** No specific persistence identified, but tool usage indicates potential threat.
- **Exfiltration (TA0010) – T1041 (Exfiltration Over C2 Channel):** No confirmed exfiltration events discovered.
- **Defense Evasion (TA0005) – T1055 (Process Injection) / SmartScreen bypass:** The user bypassed SmartScreen warnings.

---
## Summary
User **king** downloaded and executed **WebBrowserPassView.exe** on **king-vm**, successfully dumping locally stored browser credentials into **Passwords.txt**. Microsoft Defender for Endpoint alerts and Microsoft Sentinel correlation rules triggered an investigation, resulting in VM isolation and a comprehensive threat analysis. No external exfiltration was identified, though potential offline exfiltration (e.g., via USB) remains a concern. Future prevention measures include stricter controls on downloading and executing password recovery utilities, enhanced SmartScreen enforcement, and more robust credential file monitoring within Microsoft Sentinel.
