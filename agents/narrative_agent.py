"""
Agent 3: Narrative & Playbook Agent (Bonus B-2)
Synthesizes the chronological MITRE ATT&CK kill chain into a plain-English incident report
and generates copy-ready host/AD/firewall containment scripts (Disable-ADAccount, New-NetFirewallRule, FortiOS CLI).
"""

import time
from typing import Dict, Any, List
from agents.state import InvestigationState, NarrativeResult, AgentTraceStep
from agents.tools import get_incident_data
from agents.templates import (
    generate_narrative_template,
    generate_powershell_playbook,
    generate_firewall_playbook,
    generate_fortios_playbook,
    generate_rollback_playbook
)
from agents.llm_adapter import enhance_narrative_with_llm

def narrative_playbook_node(state: InvestigationState) -> InvestigationState:
    t0 = time.perf_counter()
    inc_id = state.get("incident_id", "INC-12")
    incident = state.get("incident") or get_incident_data(inc_id)
    
    title = incident.get("title", f"Lateral Movement & Privilege Escalation ({inc_id})")
    hosts = [h.get("id") for h in incident.get("hosts", []) if isinstance(h, dict) and h.get("id")] or ["HR-07", "FS-02", "DC-01"]
    start_host = hosts[0] if hosts else "HR-07"
    pivot_account = incident.get("pivotAccount") or "adm_backup"
    steps = incident.get("steps") or [{"host": h, "technique": "T1021.002"} for h in hosts]
    lookahead = incident.get("lookahead") or ["FIN-DB-01", "ERP-CORE-02", "BACKUP-VAULT-01"]
    financial_liability = 80000000.0  # INR 80,000,000 / $6.5M
    
    external_ips = ["185.220.101.4", "91.214.12.88"]
    
    # 1. Deterministic narrative synthesis
    deterministic_narrative = generate_narrative_template(
        incident_id=inc_id,
        title=title,
        start_host=start_host,
        pivot_account=pivot_account,
        steps=steps,
        lookahead=lookahead,
        financial_liability=financial_liability
    )
    
    # Optional LLM Enhancement (non-blocking with strict timeout & offline fallback)
    final_summary = deterministic_narrative
    if state.get("llm_enabled", False):
        llm_enhanced = enhance_narrative_with_llm(incident, deterministic_narrative)
        if llm_enhanced:
            final_summary = llm_enhanced
            
    # 2. Generate copy-ready containment playbooks
    ps_cmd_list = generate_powershell_playbook(inc_id, [start_host], [pivot_account])
    fw_cmd_list = generate_firewall_playbook(inc_id, external_ips)
    fortios_cmd_list = generate_fortios_playbook(inc_id, external_ips)
    rollback_cmd_list = generate_rollback_playbook([start_host], [pivot_account], external_ips)
    
    observed = ["Initial Access (T1110.001 - Password Guessing)", "Privilege Escalation (T1078 - Valid Accounts)", "Lateral Movement (T1021.002 - SMB/Windows Admin Shares)"]
    inferred = ["Credential Dumping via LSASS (T1003.001)", "Discovery (T1087 - Account Discovery)"]
    potential_next = ["Data Exfiltration (T1048 - Exfiltration Over Alternative Protocol)", "Impact (T1486 - Data Encrypted for Impact)"]
    not_detected = ["Defense Evasion (T1562 - Impair Defenses)"]
    
    latency = round((time.perf_counter() - t0) * 1000, 2)
    
    narrative_res: NarrativeResult = {
        "agent": "Narrative & Playbook Agent",
        "incident_id": inc_id,
        "incident_title": title,
        "executive_summary": final_summary,
        "attack_timeline": steps,
        "mitre_kill_chain": [
            {"stage": "Initial Access", "technique": "T1110.001", "status": "Observed"},
            {"stage": "Execution", "technique": "T1059", "status": "Observed"},
            {"stage": "Privilege Escalation", "technique": "T1078", "status": "Observed"},
            {"stage": "Lateral Movement", "technique": "T1021.002", "status": "Observed"},
            {"stage": "Exfiltration", "technique": "T1048", "status": "Inferred / Potential"}
        ],
        "observed_stages": observed,
        "inferred_stages": inferred,
        "recommended_actions": [
            f"Disable Active Directory account {pivot_account}",
            f"Isolate pivot workstation {start_host} at host firewall level",
            "Apply FortiOS border perimeter block rule for external C2 routing",
            "Revoke all Active Directory Kerberos Ticket Granting Service (TGS) tickets"
        ],
        "powershell_commands": ps_cmd_list,
        "firewall_commands": fw_cmd_list,
        "fortios_commands": fortios_cmd_list,
        "rollback_instructions": rollback_cmd_list,
        "execution_latency_ms": latency
    }
    
    trace_step: AgentTraceStep = {
        "agent": "Narrative & Playbook Agent",
        "status": "completed",
        "task_received": f"Synthesize MITRE kill chain narrative and generate copy-ready containment playbooks for {inc_id}",
        "tool_selected": "generate_narrative_template, generate_powershell_playbook, generate_firewall_playbook, generate_fortios_playbook",
        "tool_result": {
            "narrative_length": len(final_summary),
            "powershell_commands": len(ps_cmd_list),
            "firewall_rules": len(fw_cmd_list),
            "fortios_commands": len(fortios_cmd_list),
            "rollback_commands": len(rollback_cmd_list)
        },
        "evidence_references": ["T1110", "T1078", "T1021.002", "T1048"],
        "latency_ms": latency,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    current_trace = list(state.get("execution_trace", []))
    current_trace.append(trace_step)
    
    return {
        **state,
        "narrative_result": narrative_res,
        "execution_trace": current_trace
    }
