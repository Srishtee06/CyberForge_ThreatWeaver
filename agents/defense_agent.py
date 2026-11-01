"""
Agent 5: Defense Optimization Agent
Finds the most effective containment strategy to sever attacker reachability to Crown Jewels
while strictly minimizing enterprise business and operational disruption.
Uses deterministic graph cut optimization and containment simulations.
"""

from typing import Dict, Any
from datetime import datetime
from agents.state import ThreatWeaverState
from agents.tools import (
    optimize_containment_strategy,
    calculate_containment_impact,
    simulate_account_revocation,
    simulate_network_blocking
)

def defense_agent_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """LangGraph node for Agent 5: Defense Optimization Agent."""
    incident_id = state.get("incident_id", "INC-001")
    
    # 1. Execute tool calls: Find optimal containment vertex cut & assess impact
    optimal_plan = optimize_containment_strategy(incident_id)
    hosts_to_isolate = optimal_plan.get("hosts_to_isolate", ["10.10.99.1"])
    
    impact = calculate_containment_impact(hosts_to_isolate, incident_id)
    account_rev = simulate_account_revocation("adm_backup")
    net_block = simulate_network_blocking("185.220.101.4")
    
    defense_data = {
        "agent_name": "Defense Optimization Agent",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "recommended_containment_strategy": optimal_plan.get("recommended_strategy"),
        "hosts_to_isolate": hosts_to_isolate,
        "accounts_to_revoke": optimal_plan.get("accounts_to_revoke", ["adm_backup"]),
        "external_ips_to_block": optimal_plan.get("external_ips_to_block", ["185.220.101.4"]),
        "containment_impact_metrics": impact,
        "account_revocation_impact": account_rev,
        "network_blocking_impact": net_block,
        "alternative_strategies": optimal_plan.get("alternative_strategies", []),
        "justification": optimal_plan.get("justification"),
        "summary": (
            f"Recommended strategy: Isolate pivot host {hosts_to_isolate} and revoke Active Directory account 'adm_backup'. "
            f"Result: {impact.get('reachability_reduction_pct')}% reduction in Crown Jewel reachability with minimal business disruption."
        )
    }
    
    history_entry = {
        "agent": "Defense Optimization Agent",
        "status": "COMPLETED",
        "tools_executed": [
            "optimize_containment_strategy",
            "calculate_containment_impact",
            "simulate_account_revocation",
            "simulate_network_blocking"
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output_summary": defense_data["summary"]
    }
    
    history = list(state.get("execution_history", []))
    history.append(history_entry)
    
    completed = list(state.get("completed_agents", []))
    if "Defense Optimization Agent" not in completed:
        completed.append("Defense Optimization Agent")
        
    return {
        **state,
        "defense_plan_data": defense_data,
        "execution_history": history,
        "completed_agents": completed,
        "current_agent": "Defense Optimization Agent"
    }

