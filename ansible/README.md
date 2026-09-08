# Ansible — Endpoint Deployment Orchestration

This does **not** replace `Deploy-WazuhAgent.ps1`, `Deploy-Sysmon.ps1`,
`Deploy-Osquery.ps1`, or `Deploy-FIM.ps1` — it runs the exact same scripts,
just across every host in the inventory in one command instead of logging
into each machine by hand.

## Why this exists

Before this, onboarding a new endpoint meant RDP-ing into it and running 4
separate PowerShell scripts one at a time. With 5 machines that's 20 manual
steps; with 50 machines it doesn't scale at all. Ansible's inventory file is
the single place that lists every endpoint — one command deploys all 4
tools to all of them.

## Prerequisites

- Ansible installed on your control machine (`pip install ansible` — free)
- The `ansible.windows` collection: `ansible-galaxy collection install ansible.windows`
- WinRM enabled on each target Windows endpoint:
  ```powershell
  # Run once on each target, as Administrator
  winrm quickconfig -q
  Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
  ```

## Firewall / port impact

Ansible connects to each endpoint over **WinRM (TCP 5985)** — this is an
extra inbound port on endpoints that the individual Deploy-*.ps1 scripts
don't need on their own (those are push-only from Vector's perspective, but
Ansible has to reach *in* to trigger them). Scope 5985 to your management
subnet only, same principle as the Wazuh manager API in this lab's own
`docker-compose.yml`.

## Setup

1. Copy `inventory.ini` to `inventory.local.ini` (gitignored) and fill in
   real hostnames/IPs and credentials — never commit real credentials here.
2. Better: don't put credentials in the inventory file at all — pull them
   from Vault at runtime (`lookup('community.hashi_vault.vault_read', ...)`)
   once the Platform Hardening profile's Vault is deployed.

## Run

```bash
cd ansible
ansible-playbook -i inventory.local.ini playbooks/deploy-endpoint-agents.yml \
  -e vector_host=192.168.10.30 -e wazuh_manager_host=192.168.10.30
```

Test against one host first:
```bash
ansible-playbook -i inventory.local.ini playbooks/deploy-endpoint-agents.yml \
  --limit WIN-DC01 -e vector_host=192.168.10.30
```

## What it does, per host

1. Copies the 4 tool folders from `endpoint-configs/windows/` to the
   endpoint's local staging directory.
2. Runs `Deploy-WazuhAgent.ps1`, `Deploy-Sysmon.ps1`, `Deploy-Osquery.ps1`,
   `Deploy-FIM.ps1` in that order.
3. Prints a per-host OK/FAILED summary for all 4.

WDAC (`endpoint-configs/windows/wdac/Deploy-WDAC.ps1`) is deliberately **not**
included in this playbook — it forces a reboot and should be rolled out
one host at a time with manual audit-log review, not mass-deployed.
