"""
ThreatWeaver Central LangGraph Orchestrator & Supervisor Node.
Manages the shared state, conditional routing, execution loops, and multi-agent coordination.
"""

import time
from typing import Dict, Any, Literal
from datetime import datetime
from langgraph.graph import StateGraph, START, END

from agents.state import ThreatWeaverState
from agents.investigation_agent import investigation_agent_node
from agents.attack_path_agent import attack_path_agent_node
from agents.threat_intel_agent import threat_intel_agent_node
from agents.predictive_agent import predictive_agent_node
from agents.defense_agent import defense_agent_node
from agents.forensics_agent import forensics_agent_node
from agents.governance_agent import governance_agent_node

# ==============================================================================
# SUPERVISOR / ORCHESTRATOR NODE
# ==============================================================================

def supervisor_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """
    Central Supervisor: Evaluates current state, checks execution limits,
    resolves dependencies, and determines the next agent to dispatch.
    """
    iteration = state.get("iteration_count", 0) + 1
    max_iterations = state.get("max_iterations", 12)
    completed = state.get("completed_agents", [])
    
    # Check execution boundaries to prevent infinite loops
    if iteration > max_iterations:
        return {
            **state,
            "iteration_count": iteration,
            "next_step": "finalize",
            "errors": state.get("errors", []) + ["Reached maximum supervisor iteration limit."]
        }
        
    # Check conditional investigation loop
    if state.get("needs_more_evidence", False) and iteration < 3:
        return {
            **state,
            "iteration_count": iteration,
            "next_step": "investigation",
            "needs_more_evidence": False
        }
        
    # Conditional Routing Logic
    next_agent = "finalize"
    
    # 1. Start with Investigation Agent
    if "Investigation Agent" not in completed:
        next_agent = "investigation"
        
    # 2. Reconstruct Attack Path if investigation findings exist
    elif "Attack Path Reconstruction Agent" not in completed and state.get("investigation_findings"):
        next_agent = "attack_path"
        
    # 3. Enrich external IPs if suspicious indicators detected
    elif "Threat Intelligence Agent" not in completed and state.get("target_ips"):
        next_agent = "threat_intel"
        
    # 4. Predict next moves if attack path is reconstructed
    elif "Predictive Attack Agent" not in completed and state.get("attack_path_data"):
        next_agent = "predictive"
        
    # 5. Optimize defense if critical assets are at risk
    elif "Defense Optimization Agent" not in completed and state.get("predictions_data"):
        next_agent = "defense"
        
    # 6. Gather forensics if defense plan and attack path are available
    elif "Forensics and Evidence Agent" not in completed and state.get("defense_plan_data"):
        next_agent = "forensics"
        
    # 7. Validate with Response Governance
    elif "Response Governance and Validation Agent" not in completed and state.get("defense_plan_data"):
        next_agent = "governance"
        
    else:
        next_agent = "finalize"
        
    return {
        **state,
        "iteration_count": iteration,
        "next_step": next_agent,
        "current_agent": "Supervisor"
    }

def route_next_agent(state: ThreatWeaverState) -> Literal[
    "investigation",
    "attack_path",
    "threat_intel",
    "predictive",
    "defense",
    "forensics",
    "governance",
    "finalize"
]:
    """Conditional routing function for the Supervisor."""
    return state.get("next_step", "finalize")

def finalize_investigation_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """Final synthesis node compiling findings from all agents into a unified incident dossier."""
    summary = {
        "incident_id": state.get("incident_id", "INC-001"),
        "orchestration_status": "SUCCESS",
        "total_agents_executed": len(state.get("completed_agents", [])),
        "completed_agents": state.get("completed_agents", []),
        "supervisor_iterations": state.get("iteration_count", 0),
        "overall_severity": state.get("investigation_findings", {}).get("initial_severity", "CRITICAL"),
        "primary_threat_summary": state.get("forensics_report_data", {}).get("summary", "Investigation complete."),
        "human_approval_required": state.get("human_approval_required", False),
        "human_approval_status": state.get("human_approval_status", "APPROVED"),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    return {
        **state,
        "final_summary": summary,
        "current_agent": "Final Dossier"
    }

# ==============================================================================
# BUILD AND COMPILE LANGGRAPH STATEGRAPH
# ==============================================================================

def create_threatweaver_graph():
    """Create and compile the LangGraph 7-agent cybersecurity StateGraph."""
    workflow = StateGraph(ThreatWeaverState)
    
    # 1. Register Supervisor and Agent Nodes
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("investigation", investigation_agent_node)
    workflow.add_node("attack_path", attack_path_agent_node)
    workflow.add_node("threat_intel", threat_intel_agent_node)
    workflow.add_node("predictive", predictive_agent_node)
    workflow.add_node("defense", defense_agent_node)
    workflow.add_node("forensics", forensics_agent_node)
    workflow.add_node("governance", governance_agent_node)
    workflow.add_node("finalize", finalize_investigation_node)
    
    # 2. Initial entry from START to Supervisor
    workflow.add_edge(START, "supervisor")
    
    # 3. Conditional routing from Supervisor out to specialists or completion
    workflow.add_conditional_edges(
        "supervisor",
        route_next_agent,
        {
            "investigation": "investigation",
            "attack_path": "attack_path",
            "threat_intel": "threat_intel",
            "predictive": "predictive",
            "defense": "defense",
            "forensics": "forensics",
            "governance": "governance",
            "finalize": "finalize"
        }
    )
    
    # 4. Each specialist returns back to the Supervisor for next dispatch
    workflow.add_edge("investigation", "supervisor")
    workflow.add_edge("attack_path", "supervisor")
    workflow.add_edge("threat_intel", "supervisor")
    workflow.add_edge("predictive", "supervisor")
    workflow.add_edge("defense", "supervisor")
    workflow.add_edge("forensics", "supervisor")
    workflow.add_edge("governance", "supervisor")
    
    # 5. Finalize node connects to END
    workflow.add_edge("finalize", END)
    
    return workflow.compile()

# Pre-compiled orchestrator graph instance
orchestrator_graph = create_threatweaver_graph()

def run_multi_agent_investigation(incident_id: str = "INC-1021") -> Dict[str, Any]:
    """Execute the full 7-agent LangGraph investigation pipeline on an incident."""
    initial_state: ThreatWeaverState = {
        "incident_id": incident_id,
        "target_hosts": [],
        "target_users": [],
        "target_ips": [],
        "normalized_events": [],
        "investigation_findings": None,
        "attack_path_data": None,
        "threat_intel_data": None,
        "predictions_data": None,
        "defense_plan_data": None,
        "forensics_report_data": None,
        "governance_validation_data": None,
        "execution_history": [],
        "pending_agents": [
            "Investigation Agent",
            "Attack Path Reconstruction Agent",
            "Threat Intelligence Agent",
            "Predictive Attack Agent",
            "Defense Optimization Agent",
            "Forensics and Evidence Agent",
            "Response Governance and Validation Agent"
        ],
        "completed_agents": [],
        "current_agent": "START",
        "next_step": "supervisor",
        "iteration_count": 0,
        "max_iterations": 14,
        "needs_more_evidence": False,
        "human_approval_required": False,
        "human_approval_status": "NONE",
        "human_approval_details": None,
        "errors": [],
        "final_summary": None
    }
    
    t0 = time.perf_counter()
    final_output = orchestrator_graph.invoke(initial_state)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    final_output["execution_time_ms"] = elapsed_ms
    final_output["status"] = "COMPLETED"
    return final_output

