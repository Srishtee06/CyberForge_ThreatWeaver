"""
Agent 6: Forensics and Evidence Agent
Maintains an immutable, evidence-backed investigation record.
Consolidates evidence from all specialist agents, builds a forensic timeline referencing authentic DuckDB event IDs,
and distinguishes confirmed facts from working hypotheses and telemetry gaps.
"""

from typing import Dict, Any
from datetime import datetime
from agents.state import ThreatWeaverState
from agents.tools import (
    collect_agent_evidence,
    generate_incident_timeline,
    verify_evidence_references,
    generate_forensic_report
)

def forensics_agent_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """LangGraph node for Agent 6: Forensics and Evidence Agent."""
    incident_id = state.get("incident_id", "INC-001")
    
    # 1. Execute tool calls: Gather cross-agent evidence and generate forensic report
    evidence_bundle = collect_agent_evidence(state)
    timeline = generate_incident_timeline(incident_id)
    verification = verify_evidence_references(timeline)
    forensic_report = generate_forensic_report(state)
    
    forensics_data = {
        "agent_name": "Forensics and Evidence Agent",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "evidence_ledger": evidence_bundle,
        "forensic_timeline": timeline,
        "verification_status": verification,
        "incident_report": forensic_report,
        "confirmed_findings": forensic_report.get("confirmed_findings", []),
        "unverified_hypotheses": forensic_report.get("unverified_hypotheses", []),
        "evidence_gaps": forensic_report.get("evidence_gaps", []),
        "summary": (
            f"Generated verified forensic report with {len(timeline)} timestamped milestones. "
            f"Integrity check: {verification.get('integrity_status')} ({verification.get('verified_events')} event IDs verified)."
        )
    }
    
    history_entry = {
        "agent": "Forensics and Evidence Agent",
        "status": "COMPLETED",
        "tools_executed": [
            "collect_agent_evidence",
            "generate_incident_timeline",
            "verify_evidence_references",
            "generate_forensic_report"
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output_summary": forensics_data["summary"]
    }
    
    history = list(state.get("execution_history", []))
    history.append(history_entry)
    
    completed = list(state.get("completed_agents", []))
    if "Forensics and Evidence Agent" not in completed:
        completed.append("Forensics and Evidence Agent")
        
    return {
        **state,
        "forensics_report_data": forensics_data,
        "execution_history": history,
        "completed_agents": completed,
        "current_agent": "Forensics and Evidence Agent"
    }

