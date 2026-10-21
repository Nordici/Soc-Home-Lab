
# SOC Home Lab: Attack Simulation & Detection with Wazuh

## Overview

This project documents a hands-on home lab built to practice SOC analyst skills: standing up a SIEM (Wazuh), simulating realistic attacker behavior against a Windows 11 endpoint, and analyzing the resulting detections. The goal was to understand both the **offensive** side (how common attacks work) and the **defensive** side (what a SOC analyst sees in the SIEM when they happen).

## Lab Environment

| Role | OS | IP (Host-only network) |
|---|---|---|
| SIEM Server | Ubuntu Server 26.04 (Wazuh) | 192.168.56.10 |
| Victim | Windows 11 Pro | 192.168.56.102 |
| Attacker | Kali Linux | 192.168.56.1 / 192.168.56.101 |

**Tools used:** VirtualBox, Wazuh (manager + dashboard + agent), Nmap, Hydra, xfreerdp, Responder, Hashcat.

All three machines were placed on a VirtualBox Host-only network (`192.168.56.0/24`) so the lab is fully isolated from the internet and any real-world network.

---

## Part 1 — Reconnaissance (MITRE T1046: Network Service Discovery)

Before attacking anything, the attack surface was mapped with Nmap.

```bash
nmap -sV 192.168.56.10
nmap -sV -p 22,443,1514,1515,55000 192.168.56.10
nmap -Pn -p 3389 192.168.56.102
```

**Findings:**
- The Wazuh server exposed SSH (22), the dashboard over HTTPS (443), and the Wazuh agent/API ports (1514, 1515, 55000).
- The Windows 11 host had common service ports (135, 139, 445, 3389) in a **filtered** state by default — Windows Firewall was dropping unsolicited probes rather than responding, which is the expected secure behavior.

**Takeaway:** `filtered` vs `closed` tells an analyst a lot — `filtered` means a firewall is actively blocking traffic, whereas `closed` means the host responded but nothing is listening there.

---

## Part 2 — RDP Brute Force (MITRE T1110: Brute Force)

A low-privilege test account (`labtest`) was created on the Windows host with a deliberately weak password, and RDP was enabled to simulate an exposed remote-access service.

```bash
hydra -l labtest -P passwords.txt rdp://192.168.56.102 -t 1 -V
```

**Result:** The correct password was recovered after a few attempts. Two real-world obstacles were encountered and resolved along the way:
- RDP's firewall rule group was disabled by default and had to be explicitly enabled.
- Network Level Authentication (NLA) initially blocked the brute-force tool's connection attempts (NLA authenticates *before* a full session opens, which is why it's a recommended control).
- The account initially lacked membership in the **Remote Desktop Users** group — a valid password alone wasn't enough to log in, which is a good illustration of defense-in-depth (authentication succeeding ≠ authorization succeeding).

### Detection in Wazuh

Once membership was corrected and the brute force repeated, Wazuh's MITRE ATT&CK module automatically tagged the activity:

| Rule ID | Description | MITRE ID | Level |
|---|---|---|---|
| 60122 | Logon Failure – Unknown user or bad password | T1531 | 5 |
| 92657 | Successful Remote Logon Detected | T1550.002, T1078.002, T1021 | 6 |
| 60179 | Remote Desktop Users Group membership change | T1484, T1021 | 10 |

This produced a clean, correlatable timeline: failed logons → group membership change → successful remote logon — exactly the kind of chain a SOC analyst would use to justify escalating an alert.

---

## Part 3 — Post-Access Enumeration (MITRE TA0004: Privilege Escalation)

After obtaining low-privilege RDP access, standard privilege-escalation checks were run to see whether the compromised account could be escalated to admin/SYSTEM:

```powershell
whoami /priv
Get-WmiObject win32_service | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *'}
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
cmdkey /list
Get-ChildItem -Path C:\Users\ -Recurse -Include *.txt,*.config,*password*
icacls "C:\Program Files (x86)\ossec-agent"
```

**Result: no viable escalation path was found.**
- No dangerous token privileges (`SeImpersonate`, `SeDebug`, etc.) were assigned to the low-privilege account.
- No unquoted service paths existed.
- Scheduled tasks were all standard Microsoft-signed tasks.
- No credentials or passwords were stored in plaintext.
- Sensitive directories (e.g., the Wazuh agent folder) correctly denied access.

**Takeaway:** A well-configured, patched Windows 11 install resists common local privilege escalation techniques. "No escalation path found" is itself a valid and useful finding to document in an assessment.

---

## Part 4 — LLMNR/MDNS Poisoning & Credential Capture (MITRE T1557.001)

This technique required **no misconfiguration or manual setting changes** on the victim — it abuses a Windows feature (LLMNR/NBT-NS/MDNS name resolution) that is enabled by default.

**Attack flow:**
1. A listener was started on the attacker machine:
   ```bash
   sudo responder -I vboxnet0
   ```
2. On the Windows host, a request was made to a nonexistent network share (`\\FILESERVER01\share`), as would happen naturally from a typo or misconfigured mapped drive.
3. Windows broadcast "does anyone know this name?" over LLMNR/MDNS. Responder answered as if it *were* that host.
4. Windows attempted SMB authentication against the attacker, leaking an **NTLMv2 hash** for the active user account.

### Credential Cracking

```bash
hashcat -m 5600 hash.txt wordlist.txt
```

The hash was not present in a standard large wordlist (rockyou.txt), demonstrating that even a simple password can resist common dictionary attacks. It was cracked instantly once the correct password was added to a small targeted list — illustrating how real attackers build custom wordlists (company names, dates, patterns) rather than relying on generic dictionaries alone.

### Detection Gap (Important Finding)

This attack **did not appear in Wazuh** (a host-based IDS/SIEM). LLMNR poisoning happens at the network layer and does not generate a standard Windows Security Event Log entry, so a host-based agent alone cannot see it.

**Conclusion:** A mature SOC needs both:
- **HIDS** (Wazuh) — for host-level visibility (logons, file integrity, process activity)
- **NIDS** (e.g., Suricata, Zeek) — for network-level visibility (poisoning, scanning, suspicious traffic patterns)

Relying on only one creates a blind spot, which is exactly what was observed here.

**Mitigation (documented, not yet implemented in this lab):** Disable LLMNR and NBT-NS via Group Policy / registry, since modern networks rely on DNS and do not need these legacy broadcast protocols.

---

## Skills Demonstrated

- Standing up and configuring a Wazuh SIEM from scratch (manager, dashboard, agent deployment)
- Building and customizing Discover/Threat Hunting views for triage
- Reconnaissance and service enumeration (Nmap)
- Credential attacks (Hydra brute force, Responder poisoning, Hashcat cracking)
- Windows privilege escalation enumeration methodology
- Mapping observed activity to the MITRE ATT&CK framework
- Identifying detection coverage gaps between host-based and network-based monitoring

## Next Steps

- [ ] Disable LLMNR/NBT-NS and re-test to confirm the attack is blocked
- [ ] Deploy a network IDS (Suricata) alongside Wazuh to close the detection gap
- [ ] Build a custom Wazuh correlation rule that raises a single high-severity alert when brute-force + successful logon occur in sequence
- [ ] Extend the lab with Active Directory to practice lateral movement and Kerberos-based attacks

---

*This lab was built for personal learning purposes in an isolated, non-production virtual network. No real systems, networks, or credentials were targeted.*
