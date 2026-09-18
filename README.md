# AD-Diagnostic-Toolkit

A read-only Active Directory health check with a point-and-click interface. It wraps `dcdiag.exe`, `repadmin.exe`, `nltest.exe`, and `w32tm.exe`, plus a set of native directory checks, behind one window so you can pick exactly which tests to run and against which domain controllers.

Stop by https://m365admintools.com/ad-diagnostics for more information.

Every result gets a Pass, Warn, Fail, or Error status with a one-line summary, and the full raw tool output is kept in the detail pane. Export the grid as CSV for your own tracking, or a self-contained HTML report for the customer or the ticket.

<!-- Add a screenshot of the main window with results here, then uncomment:
![Main window](docs/images/main-window.png)
-->

<img width="979" height="810" alt="image" src="https://github.com/user-attachments/assets/4f4c3b0f-cbe8-4d53-b589-a049c2f63eb6" />


## Requirements

| Item | Requirement |
|---|---|
| PowerShell | Windows PowerShell 5.1 on Windows |
| Command line tools | `dcdiag.exe`, `repadmin.exe`, `nltest.exe`, and `w32tm.exe` on PATH |
| Where to run it | On a domain controller, or on an admin workstation with line of sight and rights into the target environment |
| Rights | Runs in the current user's security context. Domain Admin or equivalent read rights on the domain controllers being tested |

On an admin workstation, the command line tools come from the "RSAT: Active Directory Domain Services and Lightweight Directory Tools" Windows feature.

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Quick start

```powershell
# Use the current domain context
.\AD-DiagnosticTool.ps1

# Bind to a specific domain controller or DNS domain
.\AD-DiagnosticTool.ps1 -Server dc01.contoso.com
```

If the script is blocked on first run:

```powershell
Unblock-File .\AD-DiagnosticTool.ps1
```

Then, in the window:

1. Connect. The tool enumerates the domain controllers in the domain with their site, OS version, IP, and global catalog state.
2. Tick which domain controllers are in scope. Per-DC tests run once per checked controller. Domain-wide tests run once regardless of how many are ticked.
3. Choose tests from the categorized checklist, or use a preset: Quick Health Check, Select All, Select None.
4. Run.
5. Select any row to read the full raw output underneath the grid.
6. Export CSV, the HTML report, or both.

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Server` | string | Current domain context | Domain controller or DNS domain name to bind to at connect |

## Tests

**DCDiag**

Connectivity, Advertising, FRS Event Log, DFSR Event Log, SYSVOL Check, KCC Event Log, Knows Of Role Holders, Machine Account, Naming Context Security Descriptor, NetLogons, Objects Replicated, Replications, RID Manager, Services, System Log, Verify References, and DNS Health are all in the Quick Health Check preset.

Check SD Reference Domain, Cross-Reference Validation, Locator Check, Intersite, Topology, and Verify Enterprise References are available but unticked by default, because they are slower or noisier than the rest.

**Replication**

| Test | Scope | Default |
|---|---|---|
| Replication Summary | Domain-wide | On |
| Show Replication Status | Per DC | On |
| Replication Queue | Per DC | Off |
| Bridgehead Servers | Domain-wide | Off |
| Recalculate Topology (KCC) | Per DC | Off, and marked in red. See below |

**Netlogon**

Netlogon Service Query and DC Site Assignment run per domain controller. DC List and Domain Trusts run once for the domain. Locate DC is available but off by default.

**Directory Health**

FSMO Role Holders, Domain Controller Inventory, DNS SRV Records, SYSVOL and NETLOGON Shares, Time Sync, and an Event Log Scan covering the last 24 hours are on by default. Password and Lockout Policy, Tombstone Lifetime, and AD Recycle Bin Status are available and off by default.

## What it changes

Every test is read-only with one exception, which is unticked by default and marked in red in the checklist.

**Recalculate Topology (KCC)** runs `repadmin /kcc`, which forces the Knowledge Consistency Checker to recompute the replication topology on the target domain controller. This is a normal operational action rather than a destructive one, but it is a write and it should be a deliberate choice. Everything else reads.

## How to read the results

Status is a heuristic based on tool exit codes and known output text patterns. It is a triage aid, not a verdict.

- Read the raw output in the detail pane before acting on a **Fail**. The underlying tools report failures in ways that do not always mean what the wording suggests.
- A **Pass** means nothing obviously wrong was found by that test. It is not a certification of health.
- An **Error** means the test itself could not complete, usually a rights, name resolution, or connectivity problem rather than a finding about the directory.

## Output

**Results grid.** Domain controller, category, test, status, and summary per row, with the complete raw output for the selected row shown underneath.

**CSV export (F7).** The grid as data, for tracking findings across sites or over time.

**HTML report (F8).** A self-contained file suitable for sending to a customer or attaching to a ticket.

## Keyboard shortcuts

| Key | Action |
|---|---|
| F5 | Run diagnostics |
| F6 | Cancel |
| F7 | Export CSV |
| F8 | Export HTML report |
| Esc | Close |

## Limitations

- No alternate credential handling. The tool runs as the account that launched it, the same way `dcdiag` does when run by hand. Use a session started as the right account.
- The interface is WinForms, so Windows only, and Windows PowerShell 5.1 rather than PowerShell 7.
- Results are point-in-time. A replication failure that has since cleared still appears in the event log scan, and one that starts after the run does not appear at all.
- Test coverage is the domain bound at connect. Other domains in the forest need a separate run bound to a controller in that domain.

## Related

- AD Attribute Editor, the write-capable companion tool for bulk attribute changes
- Free Microsoft 365, Active Directory, and Veeam tools at [m365admintools.com](https://m365admintools.com)

## Author

Charles Arconi, [m365admintools.com](https://m365admintools.com)

## License

MIT. See [LICENSE](LICENSE).
