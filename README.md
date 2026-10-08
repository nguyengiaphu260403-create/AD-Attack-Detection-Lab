# Active Directory Attack & Detection Lab

A purple-team / detection-engineering lab that simulates an Active Directory attack chain and validates Windows + Sysmon telemetry in Splunk.

## Attack chain

```text
Recon / LDAP Enumeration
        ↓
Kerberoasting
        ↓
Service-account access / Lateral Movement
        ↓
LSASS Credential Access
        ↓
DCSync
        ↓
KRBTGT compromise
        ↓
Golden Ticket
        ↓
Remote service access
```

## Repository structure

```text
.
├── README.md
├── docs/
│   ├── detection-engineering.md
│   └── attack-chain.md
├── lab/
│   ├── 01-ad-setup.md
│   ├── 02-workstation-and-spn.md
│   ├── 03-logging-and-telemetry.md
│   └── 04-attack-phases.md
├── detections/
│   ├── sigma/windows/
│   └── splunk/
├── evidence/
└── scripts/
```

## Lab architecture

| Host | Role |
|---|---|
| DC01 | AD DS, DNS, KDC, Security log |
| WS01 | Domain workstation, Sysmon |
| Kali | Attacker simulation / validation |
| Splunk | SIEM / detection validation |

Domain: `lab.local` · NetBIOS: `LAB`

## Detection philosophy

The project does not treat a single Event ID as proof of compromise. Detections use event context, source/destination, account, Logon ID/GUID, process tree, baseline and time correlation.

## Important

This repository is intended for an isolated lab. The public version replaces passwords, hashes, keys and domain SID with placeholders. Do not commit real credentials, tokens, private keys or production logs.

## ATT&CK coverage

- T1558.003 — Kerberoasting
- T1021.002 — SMB/Windows Admin Shares / remote service execution context
- T1003.001 — LSASS Memory
- T1003.006 — DCSync
- T1550.002 — Pass the Hash
- T1550.003 — Pass the Ticket
- T1558.001 — Golden Ticket
