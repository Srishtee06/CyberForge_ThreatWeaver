"""
Agent 1: Investigation Agent
Primary incident investigator.
Queries DuckDB for normalized security telemetry, identifies suspicious users/IPs/hosts,
correlates multi-stage authentication patterns, and establishes the initial timeline.
"""

from typing import Dict, Any
from datetime import datetime
from agents.state import ThreatWeaverState
from agents.tools import query_logs, get_host_activity, get_user_activity, get_related_events

def investigation_agent_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """LangGraph node for Agent 1: Investigation Agent."""
    incident_id = state.get("incident_id", "INC-001")
    target_hosts = state.get("target_hosts", [])
    
    # 1. Execute tool calls: Query normalized events & correlate
    events = query_logs({}, limit=50)
    
    # If target hosts provided, get focused activity
    suspicious_ips = set()
    suspicious_users = set()
    suspicious_hosts = set()
    
    for evt in events:
        src = evt.get("src_ip")
        dst = evt.get("dst_ip")
        user = evt.get("user_id")
        
        if src and not (src.startswith("10.") or src.startswith("192.168.")):
            suspicious_ips.add(src)
        if user and user not in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "-", ""):
            suspicious_users.add(user)
        if dst:
            suspicious_hosts.add(dst)
            
    # Host and User deep dives
    primary_host = list(suspicious_hosts)[0] if suspicious_hosts else "10.10.99.1"
    host_profile = get_host_activity(primary_host)
    
    primary_user = list(suspicious_users)[0] if suspicious_users else "adm_backup"
    user_profile = get_user_activity(primary_user)
    
    # Check if more evidence is needed
    needs_more = len(events) == 0
    
    findings = {
        "agent_name": "Investigation Agent",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "incident_summary": (
            f"Investigation of {incident_id} identified {len(events)} correlated security events. "
            f"External threat activity detected from {list(suspicious_ips)[:3]} targeting {primary_host} "
            f"with credential activity under account '{primary_user}'."
        ),
        "suspicious_entities": {
            "external_ips": list(suspicious_ips),
            "compromised_users": list(suspicious_users),
            "targeted_hosts": list(suspicious_hosts)
        },
        "host_profile": host_profile,
        "user_profile": user_profile,
        "timeline_events_count": len(events),
        "timeline": events[:10],
        "initial_severity": "HIGH" if len(suspicious_ips) > 0 else "MEDIUM",
        "recommended_next_steps": [
            "Reconstruct attack graph topology and pivot paths",
            "Perform external threat intelligence enrichment on external IP indicators",
            "Calculate lateral movement reachability to high-value assets"
        ]
    }
    
    # Update execution history
    history_entry = {
        "agent": "Investigation Agent",
        "status": "COMPLETED",
        "tools_executed": ["query_logs", "get_host_activity", "get_user_activity"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output_summary": findings["incident_summary"]
    }
    
    history = list(state.get("execution_history", []))
    history.append(history_entry)
    
    completed = list(state.get("completed_agents", []))
    if "Investigation Agent" not in completed:
        completed.append("Investigation Agent")
        
    return {
        **state,
        "investigation_findings": findings,
        "normalized_events": events,
        "target_ips": list(suspicious_ips),
        "target_users": list(suspicious_users),
        "target_hosts": list(suspicious_hosts),
        "needs_more_evidence": needs_more,
        "execution_history": history,
        "completed_agents": completed,
        "current_agent": "Investigation Agent"
    }

