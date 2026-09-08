# WDAC — Application Whitelisting (Prevention, not Detection)

Every endpoint control deployed so far in this lab — Wazuh, Sysmon, osquery,
the custom FIM watcher — only **detects and reports**. WDAC is the first one
that actually **blocks** execution: only applications covered by the policy's
rules (Publisher-signed, or explicitly hashed) are allowed to run.

## Why this is deployed carefully, in stages

A bad WDAC policy can make a machine unable to run anything at all — this is
not something to roll out the way Sysmon or osquery were. `Deploy-WDAC.ps1`
deliberately:

1. **Generates the policy from what's actually installed** on the target
   machine (`New-CIPolicy -Level Publisher -Fallback Hash`) rather than a
   hand-written rule set — Microsoft's own recommended starting point.
2. **Forces AUDIT mode** (`Set-RuleOption ... -Option 3`) — nothing is
   blocked. Anything that *would* have been blocked is logged as Event ID
   3076 in `CodeIntegrity/Operational`, so the impact is visible before any
   enforcement happens.
3. **Never auto-enforces.** Moving from audit to enforced is a manual,
   deliberate step documented at the end of a deploy run — only after
   reviewing at least a week of audit logs with zero unexpected hits.

## Firewall / port impact

**None.** WDAC is a local kernel-mode policy — no network activity, no port.

## Deploy

```powershell
# Run as Administrator, on Windows 10/11 Enterprise/Education or Server 2016+
.\Deploy-WDAC.ps1
```

Reboot is required afterward for the policy to load. The machine keeps
running exactly as before — audit mode logs, never blocks.

## Reviewing audit hits

```powershell
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
  Where-Object { $_.Id -eq 3076 }
```

Every 3076 event is something that would be blocked in enforced mode.
Investigate each one — a legitimate but unsigned internal tool needs an
explicit hash rule added before enforcement, or it will break for every user.

## Moving to enforced mode (manual, once confident)

```powershell
Set-RuleOption -FilePath C:\ProgramData\SOCLab\WDAC\SOCLab-WDAC-Audit.xml -Option 3 -Delete
ConvertFrom-CIPolicy -XmlFilePath C:\ProgramData\SOCLab\WDAC\SOCLab-WDAC-Audit.xml `
  -BinaryFilePath C:\ProgramData\SOCLab\WDAC\SOCLab-WDAC-Audit.cip
Copy-Item C:\ProgramData\SOCLab\WDAC\SOCLab-WDAC-Audit.cip `
  "$env:windir\System32\CodeIntegrity\CiPolicies\Active\" -Force
# Reboot again to apply
```

## Uninstall

```powershell
.\Deploy-WDAC.ps1 -Uninstall
```

Removes the local work directory. The active `.cip` policy under
`CodeIntegrity\CiPolicies\Active\` must be removed by hand and the machine
rebooted — this is intentional, so a policy is never silently dropped.
