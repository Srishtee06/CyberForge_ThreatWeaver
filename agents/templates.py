"""
Deterministic Templates for ThreatWeaver 4-Agent Architecture
Used in Mode A (Offline-First) to generate structured narratives, playbooks, explanations, and Sigma rules.
"""

def generate_narrative_template(
    incident_id: str,
    title: str,
    start_host: str,
    pivot_account: str,
    steps: list,
    lookahead: list,
    financial_liability: float
) -> str:
    observed_steps = [s for s in steps if s.get("status", "observed").lower() != "inferred"]
    inferred_steps = [s for s in steps if s.get("status", "observed").lower() == "inferred"]
    
    lines = [
        f"Executive Impact Briefing for Incident [{incident_id}]:",
        f"Title: {title}",
        f"Initial intrusion originated on endpoint [{start_host}] utilizing compromised credentials for [{pivot_account}].",
        f"The attack progressed across {len(observed_steps)} observed stages with verified evidence references."
    ]
    
    if inferred_steps:
        lines.append(f"An additional {len(inferred_steps)} lateral movement pivot(s) were inferred based on active sessions.")
        
    if lookahead:
        targets_str = ", ".join([t if isinstance(t, str) else (t.get("host") or t.get("target_node", "Unknown")) for t in lookahead[:3]])
        lines.append(f"Look-Ahead Assessment: Account [{pivot_account}] retains active privileges to reach {len(lookahead)} downstream production servers ({targets_str}) with an estimated financial exposure of INR {financial_liability:,.0f}." if financial_liability else f"Look-Ahead Assessment: Account [{pivot_account}] retains active privileges to reach {len(lookahead)} downstream production servers ({targets_str}).")

    lines.append("Recommended immediate containment: Isolate initial access pivot hosts and revoke Kerberos ticket-granting tokens.")
    return "\n".join(lines)


def generate_powershell_playbook(incident_id: str, hosts: list, accounts: list) -> list:
    cmds = [
        f"# ThreatWeaver Automated Containment Playbook (Incident {incident_id})",
        "# Requires SOC Analyst Authorization before execution."
    ]
    for acc in accounts:
        clean_acc = acc.replace("user:", "").replace("account:", "")
        cmds.extend([
            f"# Revoke Kerberos tickets and disable compromised account: {clean_acc}",
            f'Revoke-ADUserTicket -Identity "{clean_acc}" -ErrorAction SilentlyContinue',
            f'Disable-ADAccount -Identity "{clean_acc}" -Confirm:$false'
        ])
    for h in hosts:
        cmds.extend([
            f"# Isolate host {h} from internal enterprise subnets",
            f'New-NetFirewallRule -DisplayName "ThreatWeaver-Quarantine-{h}" -Direction Outbound -Action Block -Profile Any -RemoteAddress "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"',
            f'New-NetFirewallRule -DisplayName "ThreatWeaver-Quarantine-In-{h}" -Direction Inbound -Action Block -Profile Any -RemoteAddress "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"'
        ])
    return cmds


def generate_firewall_playbook(incident_id: str, external_ips: list) -> list:
    cmds = [f"# Windows Defender Perimeter Firewall Block Rules ({incident_id})"]
    for ip in external_ips:
        cmds.append(f'netsh advfirewall firewall add rule name="ThreatWeaver-Block-{ip}" dir=in action=block remoteip={ip}')
    return cmds


def generate_fortios_playbook(incident_id: str, external_ips: list) -> list:
    cmds = [
        f"# FortiOS Firewall CLI Quarantine Script (Incident {incident_id})",
        "config firewall address"
    ]
    for ip in external_ips:
        name = f"THREATWEAVER_{ip.replace('.', '_')}"
        cmds.extend([
            f'    edit "{name}"',
            f'        set subnet {ip}/32',
            f'        set comment "Automated ThreatWeaver Quarantine for {incident_id}"',
            "    next"
        ])
    cmds.extend([
        "end",
        "config firewall policy",
        f'    # Prepend drop policy for quarantined addresses in {incident_id}',
        "end"
    ])
    return cmds


def generate_rollback_playbook(hosts: list, accounts: list, external_ips: list) -> list:
    cmds = [
        "# Rollback / Restoration Playbook",
        "# Re-enables accounts and removes containment rules after incident resolution"
    ]
    for acc in accounts:
        clean_acc = acc.replace("user:", "").replace("account:", "")
        cmds.append(f'Enable-ADAccount -Identity "{clean_acc}"')
    for h in hosts:
        cmds.extend([
            f'Remove-NetFirewallRule -DisplayName "ThreatWeaver-Quarantine-{h}" -ErrorAction SilentlyContinue',
            f'Remove-NetFirewallRule -DisplayName "ThreatWeaver-Quarantine-In-{h}" -ErrorAction SilentlyContinue'
        ])
    for ip in external_ips:
        cmds.append(f'netsh advfirewall firewall delete rule name="ThreatWeaver-Block-{ip}"')
    return cmds


def generate_sigma_yaml_template(
    title: str,
    rule_id: str,
    description: str,
    technique_id: str,
    stage: str,
    selection_dict: dict,
    level: str = "high"
) -> str:
    selection_yaml_lines = []
    import json
    for k, v in selection_dict.items():
        if isinstance(v, list):
            items = ", ".join([json.dumps(str(x)) for x in v])
            selection_yaml_lines.append(f"        {k}: [{items}]")
        else:
            selection_yaml_lines.append(f'        {k}: {json.dumps(str(v))}')
    
    sel_block = "\n".join(selection_yaml_lines) if selection_yaml_lines else '        EventID: 5140'
    
    clean_stage = stage.lower().replace(" ", "_")
    return f"""title: "{title}"
id: {rule_id}
status: experimental
description: "{description}"
references:
    - https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/
author: "ThreatWeaver Adaptive Rule Agent"
date: "2026-11-01"
logsource:
    category: network_connection
    product: windows
detection:
    selection:
{sel_block}
    condition: selection
falsepositives:
    - Authorized administrative maintenance
    - Scheduled vulnerability scanning
level: {level}
tags:
    - attack.{clean_stage}
    - attack.{technique_id.lower()}
"""
