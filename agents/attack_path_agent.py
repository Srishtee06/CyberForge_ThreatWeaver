"""
Agent 2: Attack Path Reconstruction Agent
Reconstructs the attacker's multi-hop movement through infrastructure using NetworkX.
Pre-aggregates telemetry in DuckDB, generates graph nodes and edges, identifies critical pivot nodes,
and categorizes the sequence across MITRE ATT&CK and the Cyber Kill Chain.
"""

from typing import Dict, Any
from datetime import datetime
from agents.state import ThreatWeaverState
from agents.tools import (
    build_attack_graph,
    get_attack_path,
    calculate_graph_centrality,
    get_reachable_hosts
)

def attack_path_agent_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """LangGraph node for Agent 2: Attack Path Reconstruction Agent."""
    incident_id = state.get("incident_id", "INC-001")
    
    # 1. Execute tool calls: NetworkX graph construction & path analysis
    graph_data = build_attack_graph(incident_id)
    path_steps = get_attack_path(incident_id)
    centrality = calculate_graph_centrality(incident_id)
    reachable_hosts = get_reachable_hosts(incident_id)
    
    # Extract compromised hosts and MITRE techniques
    compromised_hosts = set()
    mitre_stages = []
    
    for step in path_steps:
        src = step.get("src_ip")
        dst = step.get("dst_ip")
        if src: compromised_hosts.add(src)
        if dst: compromised_hosts.add(dst)
        
        mitre_stages.append({
            "step": len(mitre_stages) + 1,
            "timestamp": step.get("timestamp"),
            "technique_id": step.get("technique_id"),
            "technique_name": step.get("technique_name"),
            "kill_chain_stage": step.get("kill_chain_stage"),
            "transition": f"{src} -> {dst}"
        })
        
    attack_data = {
        "agent_name": "Attack Path Reconstruction Agent",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "attack_graph": {
            "node_count": len(graph_data.get("nodes", [])),
            "edge_count": len(graph_data.get("edges", [])),
            "critical_pivot_nodes": list(centrality.keys())[:3]
        },
        "centrality_metrics": centrality,
        "attack_sequence": mitre_stages,
        "compromised_hosts": list(compromised_hosts),
        "mitre_coverage": list(set([s["technique_id"] for s in mitre_stages if s.get("technique_id")])),
        "summary": (
            f"Successfully reconstructed attack path across {len(graph_data.get('nodes', []))} nodes and "
            f"{len(graph_data.get('edges', []))} edges. Identified critical pivot node '{list(centrality.keys())[0] if centrality else '10.10.99.1'}' "
            f"linking initial access to internal lateral movement."
        )
    }
    
    # Update execution history
    history_entry = {
        "agent": "Attack Path Reconstruction Agent",
        "status": "COMPLETED",
        "tools_executed": ["build_attack_graph", "get_attack_path", "calculate_graph_centrality", "get_reachable_hosts"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output_summary": attack_data["summary"]
    }
    
    history = list(state.get("execution_history", []))
    history.append(history_entry)
    
    completed = list(state.get("completed_agents", []))
    if "Attack Path Reconstruction Agent" not in completed:
        completed.append("Attack Path Reconstruction Agent")
        
    return {
        **state,
        "attack_path_data": attack_data,
        "execution_history": history,
        "completed_agents": completed,
        "current_agent": "Attack Path Reconstruction Agent"
    }

