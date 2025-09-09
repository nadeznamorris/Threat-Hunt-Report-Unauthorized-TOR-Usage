# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched in `DeviceFileEvents` for Any file related to the string `tor` and discovered that the user `lilaclab` had downloaded tor browser and did some things that created a lot of tor-related files on the desktop. There was also a `tor-shopping-list` file created on the desktop at `2025-09-04T14:06:48.2079401Z`. The incident started: `2025-09-04T13:44:56.3017635Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nadezna-sentine"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "lilaclab"
| where Timestamp >= datetime(2025-09-04T13:44:56.3017635Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ad9c5f2a-8372-4b52-836f-008235b1de39" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched in the `DeviceProcessEvents` table to see if `ProcessCommandLine` contained any string `tor-browser-windows-x86_64-portable-14.5.6.exe  /S`. Based on the log returned, on `2025-09-04T13:52:06.9481703Z`, a user named `lilaclab` on the device `nadezna-sentine` ran a program called `Tor Browser` (portable version) from their Downloads folder, using a silent installation command `(/S)`, meaning it installed without showing any prompts or windows.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "nadezna-sentine"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project Timestamp,DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="800" alt="image" src="https://github.com/user-attachments/assets/49ddfe49-c4de-48b0-84a7-0a4f94122b4f" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched in the `DeviceProcessEvents` table and it indicated that the user `lilaclab` opened the tor browser. There was evidence that the user opened it at `2025-09-04T13:52:26.6415339Z`. There were a lot of instances of `firefox.exe` (Tor) and a lot of other `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "nadezna-sentine"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp,DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/730b0ea2-fda4-40f8-9c6e-6248072858ad" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched in `DeviceNetworkEvents` table to see if the user made any connection using tor browser through the known ports. On `2025-09-04T13:53:50.546652Z`, a program called `tor.exe` was successfully run by the user `lilaclab` on the device `nadezna-sentine`. It established a successful network connection to the IP address `45.95.169.43` over port `9001`, which is commonly used by the Tor network. There were a couple of other tor connections made through port `443` as well.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "nadezna-sentine"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9050", "9150", "9030", "443", "80")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort,RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/54913e16-1987-43ed-9188-ff909c251643" />

---

## Chronological Event Timeline 

### 1. Acquisition & Download (Initial Stage)

- **Timestamp:** `2025-09-04T13:44:56.3017635Z`
- **Event:** The user "lilaclab" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\lilaclab\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Silent Installation (Execution Stage)

- **Timestamp:** `2025-09-04T13:52:06.9481703Z`
- **Event:** The user "lilaclab" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe  /S`
- **File Path:** `C:\Users\lilaclab\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "lilaclab" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\lilaclab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Browser Launch & Supporting File Creation (Setup Stage)

- **Timestamp:** `2025-09-04T13:52:26.6415339Z`
- **Event:** A network connection to IP `45.95.169.43` on port `9001` by user "lilaclab" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\lilaclab\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Network Connections to Tor Relays (Operational Stage)

- **Timestamps:**
  - `2025-09-04T13:53:53.0370423Z` - Connected to `185.220.101.198` on port `443`.
  - `2025-09-04T13:53:19.511175Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "lilaclab" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. Suspicious File Creation (Potential Intent Stage)

- **Timestamp:** `2025-09-04T14:06:48.2079401Z`
- **Event:** The user "lilaclab" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\lilaclab\Desktop\tor-shopping-list.txt`

---

## Summary

The sequence of events reflects a **purposeful installation** and use of the Tor Browser by `lilaclab`. The activity moved quickly from download (2025-09-04T13:44:56.3017635Z) to **installation** (2025-09-04T13:52:06.9481703Z) to **first connections** (2025-09-04T13:52:26.6415339Z), showing **pre-planned execution rather than accidental use**. The subsequent creation of the file `tor-shopping-list.txt` suggests **preparation for anonymized online activity**, potentially involving sensitive or illicit transactions. In short, the user **successfully leveraged Tor for anonymous network access**, and local artifacts indicate **intent for further usage**.

---

## Response Taken

TOR usage was confirmed on the endpoint `nadezna-sentine` by the user `lilaclab`. The device was isolated and the user's direct manager was notified.

---
