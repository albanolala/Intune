# ExportIntuneFW

> Export and report Microsoft Intune Endpoint Security **Firewall Policies** and **Firewall Rules** via Microsoft Graph API.

---

## Overview

Two-file toolkit that:

1. **Authenticates to Microsoft Graph** (MSAL, no ADAL dependency)
2. **Exports** all Endpoint Security Firewall policies and their rules to JSON
3. **Generates three report formats** via Python:
   - Interactive HTML dashboard (filterable tables, search, tabs)
   - Multi-sheet Excel workbook with color-coded rows
   - Flat CSV ready for Power BI or Excel import

The PowerShell script handles Graph authentication and JSON export. Python handles all parsing and report generation — this split avoids known `ConvertFrom-Json` deserialization issues in PowerShell 5.1 when dealing with single-item arrays from the Graph API.

---

## Files

| File | Purpose |
|---|---|
| `Export-IntuneFirewall-Complete.ps1` | Graph auth, policy export, JSON output |
| `generate_reports.py` | JSON parser + HTML / CSV / Excel report generator |

Both files must be in the **same folder**.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 or Windows Server | PowerShell 64-bit |
| PowerShell 5.1+ | Included in Windows 10+ |
| Python 3.8+ | [python.org](https://www.python.org/downloads/) |
| `openpyxl` Python package | Auto-installed by the script, or `pip install openpyxl` |
| `Microsoft.Graph.Authentication` | Auto-installed by the script |
| `Microsoft.Graph.DeviceManagement` | Auto-installed by the script |
| Intune RBAC permission | `DeviceManagementConfiguration.Read.All` |

> **PIM users:** activate your role **before** running the script.

---

## Usage

### Full run (Graph auth + export + reports)

```powershell
.\Export-IntuneFirewall-Complete.ps1
```

Optionally force a specific tenant (useful with Conditional Access or multi-tenant):

```powershell
.\Export-IntuneFirewall-Complete.ps1 -TenantId "contoso.onmicrosoft.com"
```

Specify a custom output folder:

```powershell
.\Export-IntuneFirewall-Complete.ps1 -OutputFolder "C:\Reports\Intune"
```

### Re-generate reports from existing JSON (no re-authentication)

After a first successful run you can iterate on the reports without hitting Graph again:

```powershell
.\Export-IntuneFirewall-Complete.ps1 -FromJson ".\IntuneFirewallExport_20260319_110000\FirewallPolicies_Full.json"
```

Or call Python directly:

```bash
python generate_reports.py ".\FirewallPolicies_Full.json" ".\OutputFolder"
```

---

## Output

Each run creates a timestamped output folder (`IntuneFirewallExport_YYYYMMDD_HHMMSS`) containing:

```
IntuneFirewallExport_20260319_110000\
    FirewallPolicies_Full.json      # Raw Graph API response (full depth)
    FirewallPolicies_Report.html    # Interactive dashboard — open in any browser
    FirewallPolicies_Rules.csv      # Flat CSV for Power BI / Excel
    FirewallPolicies_Report.xlsx    # Excel workbook (3 sheets)
```

### HTML Dashboard

Three tabs:

- **Policy** — name, source type, template ID, last modified, scope tags, rule count, assigned groups
- **Rules** — per-rule details with filterable dropdowns for action (Allow/Block), direction (Inbound/Outbound), and enabled state
- **Groups** — policy-to-AAD-group assignment mapping

### Excel Workbook

| Sheet | Content |
|---|---|
| Policy Riepilogo | All policies with baseline settings count and rule count |
| Regole Firewall | All rules — Block rows highlighted red, disabled rows highlighted orange |
| Gruppi Assegnati | Policy → assigned AAD group mapping |

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-OutputFolder` | string | Output path. Default: `.\IntuneFirewallExport_<timestamp>` |
| `-TenantId` | string | Force a specific Azure AD tenant ID |
| `-SkipModuleInstall` | switch | Do not auto-install missing PS modules |
| `-FromJson` | string | Skip Graph entirely, generate reports from existing JSON |

---

## How it works

```
PowerShell script
    │
    ├── [1] Environment checks (OS, PS version, 64-bit, DNS)
    ├── [2] Execution Policy fix (auto-remediate if not GPO-enforced)
    ├── [3] Install/import Microsoft.Graph modules
    ├── [4] Connect-MgGraph (MSAL interactive browser login)
    ├── [5] Fetch /deviceManagement/intents (legacy Intent policies)
    │       Fetch /deviceManagement/configurationPolicies (Settings Catalog)
    ├── [6] Filter by "Firewall" keyword in DisplayName
    │       Fetch /settings and /assignments for each policy
    ├── [7] Export FirewallPolicies_Full.json
    └── [8] Call generate_reports.py
                │
                ├── Parse groupSettingCollectionValue (firewall rules)
                │   Map action_type_0/1 → Block/Allow
                │   Map direction_in/out → Inbound/Outbound
                │   Map protocol numbers → TCP/UDP/ICMP/Any
                ├── Generate HTML (inline CSS + JS, no dependencies)
                ├── Generate CSV (UTF-8 BOM for Excel compatibility)
                └── Generate XLSX (openpyxl, 3 sheets, color-coded)
```

---

## Supported Policy Types

| Type | Graph Endpoint | Notes |
|---|---|---|
| Settings Catalog (post-2022) | `/configurationPolicies` | Supports Firewall Rules with full rule detail |
| Intent-based (legacy, pre-2022) | `/intents` | Firewall baseline settings |

---

## Known Limitations

- Rules with `simpleSettingCollectionValue` port lists (e.g. `"80, 443, 8080"`) are supported.
- If a policy has **no firewall keyword** in its DisplayName, the script exports all policies for manual review.
- The script requires **interactive browser login** by default. For unattended/pipeline use, replace `Connect-MgGraph` with certificate-based App Registration auth.

---

## License

MIT — see [LICENSE](LICENSE) for details.

