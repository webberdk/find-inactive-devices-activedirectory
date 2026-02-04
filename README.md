````markdown
# AD Inactive Device Review (v2.1.1)

**READ-ONLY PowerShell script** for identifying and assessing **inactive computer objects in Active Directory**, with explicit support for:

- **Servers** (Windows Server + Linux/Unix + non-client devices)
- **Clients** (Windows / macOS endpoints)
- **All devices**

The script is designed to support **security hygiene, AD governance, and server/client lifecycle management**, including **decommission (decom) readiness**.

---

## ✨ Key Features

- ✔ Detects **inactive AD computer objects**
- ✔ Supports **Servers / Clients / All** modes
- ✔ Classifies devices by OS:
  - WindowsServer
  - Linux
  - Unix
  - NonWindowsNonClient
  - Client
  - Unknown
- ✔ Read-only – **no changes made to AD**
- ✔ Optional **accurate lastLogon** across all DCs
- ✔ **Streaming CSV output** for large environments
- ✔ **Configurable AD paging size** for performance tuning
- ✔ Optional **DNS resolution / ping checks**
- ✔ **Strict allow-list filtering** per mode (with optional Unknown in Servers)
- ✔ Flags **decommission candidates**
- ✔ Produces **audit-friendly output**
- ✔ One output folder **per execution (timestamped)**

---

## 🧭 Use Cases

- AD hygiene and cleanup preparation
- Security risk identification (enabled but unused devices)
- Server / client **lifecycle & decom reviews**
- Audit and compliance evidence
- CMDB reconciliation (future extension)
- Input for Jira stories or remediation work

---

## 🛠 Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- **RSAT ActiveDirectory module**
- Read access to Active Directory
- Network access to DCs (for `-AllDCs` mode)

---

## ⚙️ Configuration (no parameters required)

All configuration is done **inside the script** in the `CONFIG` section:

```powershell
$Mode                  = "Servers"   # Servers | Clients | All
$InactiveDays          = 180
$DisableCandidateDays  = 180
$DeleteCandidateDays   = 365

$AllDCs               = $false
$SearchBase           = ""
$ResolveDns           = $false
$Ping                 = $false
$ResultPageSize        = 500
$StreamCsv             = $true
$SortCsvByDaysInactive = $false
$ExcludeUnknownOS      = $true
$IncludeUnknownInServers = $false

$RunTimestamp         = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir               = "C:\Temp\AD_InactiveDevices\$RunTimestamp"
````

### Mode explanation

| Mode      | Includes                                        | Excludes |
| --------- | ----------------------------------------------- | -------- |
| `Servers` | Windows Server, Linux, Unix, non-client devices | Clients  |
| `Clients` | Windows/macOS clients                           | Servers  |
| `All`     | Everything                                      | Nothing  |

---

## 📁 Output Structure

Each execution creates a **unique timestamped folder**:

```
C:\Temp\AD_InactiveDevices\
└── 20260201_134512\
    ├── InactiveDevices_20260201_134512.csv
    ├── InactiveDevices_20260201_134512_FindingsSummary.txt
    └── InactiveDevices_20260201_134512_RunTranscript.txt
```

---

## 📄 Output Files

### 1️⃣ CSV – `InactiveDevices_<timestamp>.csv`

Detailed inventory including:

* Device name / DNS
* Enabled / Disabled
* OS & DeviceClass
* OU path
* Last logon (effective)
* Days inactive
* SPN count
* Group membership count + sample
* Password last set / created / changed timestamps
* DNS resolution / ping results (if enabled)
* Lifecycle recommendation
* Rationale

### 2️⃣ Findings Summary – TXT

Human-readable summary with:

* Counts
* DeviceClass distribution
* Lifecycle recommendations
* Top OUs with inactive objects
* High-risk objects (SPNs)

### 3️⃣ Transcript – TXT

Full execution log for auditability.

---

## 🧠 Lifecycle Logic (READ-ONLY)

The script **does not change anything**, but suggests actions:

| Condition                                 | SuggestedLifecycleStep |
| ----------------------------------------- | ---------------------- |
| Enabled & inactive ≥ DeleteCandidateDays  | `DeleteCandidate`      |
| Enabled & inactive ≥ DisableCandidateDays | `DisableCandidate`     |
| Disabled or lower inactivity              | `Review`               |

Additional risk flags:

* Has SPNs
* Has group memberships
* Unknown OS string

---

## ⚠️ Important Notes

* `lastLogonDate` is **replicated** and approximate
  → enable `$AllDCs = $true` for maximum accuracy
* Linux/Unix devices rely on **OperatingSystem string hygiene**
* Objects with SPNs should **never be deleted blindly**
* Script intentionally avoids automation to prevent accidents
* `StreamCsv=$true` disables sorting by DaysInactive (by design)

---

## 🔒 Safety

* **No Set-AD*** commands
* **No deletes, disables, or modifications**
* Safe to run in production
* Suitable for auditors and security reviews

---

## 🚀 Running the Script

Simply edit the CONFIG section and run:

```powershell
.\Get-InactiveDevices_v2.1.ps1
```

No parameters required.

---

## 🧩 Future Extensions (Ideas)

* CMDB CSV comparison (CMDB = Decom, AD = Enabled)
* OU / owner-based action lists
* JSON output for dashboards
* Scheduled execution + retention cleanup
* Separate client/server thresholds
* Exception lists for appliances / jump hosts

---

## 📜 License

Internal / enterprise usage.
No warranty. Review output before taking action.

---

## 🤝 Contributing

Improvements are welcome:

* Additional OS patterns
* Performance optimizations
* Lifecycle logic tuning
* Reporting enhancements
