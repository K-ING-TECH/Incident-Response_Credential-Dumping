# Threat Event (Credential Dumping)
**Unauthorized Credential Dumping with WebBrowserPassView**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download WebBrowserPassView.exe from Nirsoft: https://www.nirsoft.net/utils/web_browser_password.html
2. Run it silently from the **Downloads** folder: ```WebBrowserPassView.exe /stext Passwords.txt```
3. Store the dumped credentials in a file named ```Passwords.txt``` in the **Documents** directory
4. Open ```Passwords.txt``` to verify extracted browser credentials
6. Create a folder on the desktop called ```Dumped-Creds-Folder``` and move ```Passwords.txt``` inside
7. Delete the file (and folder) to cover tracks

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceFileEvents                                                             |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table |
| **Purpose**         | Used for detecting credential dumping tool download, creation of Passwords.txt, and any subsequent moves or deletions. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                          |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table |
| **Purpose**         | Used to detect the silent execution of WebBrowserPassView.exe and verify the process lineage for potential malicious activity. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceNetworkEvents                                                          |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose**         | Used to detect any external connections, such as potential exfiltration to cloud storage or file-sharing services. |

---

## Related Queries:
```kql
// WebBrowserPassView.exe being downloaded
DeviceFileEvents
| where FileName startswith "WebBrowserPassView"

// WebBrowserPassView.exe running silently and creating Passwords.txt
DeviceProcessEvents
| where ProcessCommandLine has "WebBrowserPassView.exe"
| where ProcessCommandLine has "/stext"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Credentials file was successfully created on disk
DeviceFileEvents
| where FileName in ("Passwords.txt", "Dumped_Credentials.txt", "Logins.txt")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// Potential exfiltration via external domains
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("WebBrowserPassView.exe", "powershell.exe", "cmd.exe")
| where RemoteUrl has_any ("file.io", "anonfiles.com", "pastebin.com", "mega.nz", "transfer.sh", "wetransfer.com", "sendspace.com", "gofile.io")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// Credentials file being deleted or renamed
DeviceFileEvents
| where FileName contains "Passwords.txt"
| where ActionType in ("FileDeleted", "FileRenamed")
