"""
ThreatWeaver 4-Agent LangGraph SOC Orchestration Graph
Compiles the four specialized SOC agents into a high-performance, deterministic LangGraph workflow:
1. Provenance & Triage Agent (FR-4)
2. Blast-Radius & Look-Ahead Agent (FR-6)
3. Narrative & Playbook Agent (Bonus B-2)
4. Adaptive Rule Authoring Agent (Bonus B-4)
"""

import time
from typing import Dict, Any, List, Literal
from langgraph.graph import StateGraph, START, END

from agents.state import InvestigationState
from agents.provenance_agent import provenance_triage_node
from agents.blast_radius_agent import blast_radius_node
from agents.narrative_agent import narrative_playbook_node
from agents.rule_authoring_agent import adaptive_rule_node
from agents.tools import get_incident_data

def should_skip_containment(state: InvestigationState) -> Literal["blast_radius", "narrative_playbook"]:
    """Conditional edge: if provenance verdict is clearly benign noise, bypass heavy blast radius traversal."""
    prov = state.get("provenance_result")
    if prov and prov.get("verdict") == "likely_benign":
        return "narrative_playbook"
    return "blast_radius"

def build_soc_graph():
    """Builds and compiles the 4-agent LangGraph StateGraph."""
    workflow = StateGraph(InvestigationState)
    
    # Register 4 specialized agent nodes
    workflow.add_node("provenance_triage", provenance_triage_node)
    workflow.add_node("blast_radius", blast_radius_node)
    workflow.add_node("narrative_playbook", narrative_playbook_node)
    workflow.add_node("adaptive_rule", adaptive_rule_node)
    
    # Entry point
    workflow.add_edge(START, "provenance_triage")
    
    # Conditional routing from Provenance Agent
    workflow.add_conditional_edges(
        "provenance_triage",
        should_skip_containment,
        {
            "blast_radius": "blast_radius",
            "narrative_playbook": "narrative_playbook"
        }
    )
    
    # Sequential flow
    workflow.add_edge("blast_radius", "narrative_playbook")
    workflow.add_edge("narrative_playbook", "adaptive_rule")
    workflow.add_edge("adaptive_rule", END)
    
    return workflow.compile()

soc_compiled_graph = build_soc_graph()

def run_soc_investigation(incident_id: str, llm_enabled: bool = False) -> Dict[str, Any]:
    """
    Main entry point for 4-agent SOC investigation.
    Executes in <200ms deterministically with zero network dependencies.
    """
    t0 = time.perf_counter()
    incident = get_incident_data(incident_id)
    
    initial_state: InvestigationState = {
        "incident_id": incident_id,
        "incident": incident,
        "events": incident.get("events", []),
        "execution_trace": [],
        "errors": [],
        "llm_enabled": llm_enabled,
        "approval_required": True,
        "status": "in_progress"
    }
    
    final_state = soc_compiled_graph.invoke(initial_state)
    total_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    final_state["status"] = "completed"
    
    # Calculate summary
    prov = final_state.get("provenance_result", {})
    blast = final_state.get("blast_radius_result", {})
    narr = final_state.get("narrative_result", {})
    sigma = final_state.get("sigma_result", {})
    
    return {
        "incident_id": incident_id,
        "status": "completed",
        "total_latency_ms": total_latency_ms,
        "provenance_triage": prov,
        "blast_radius": blast,
        "narrative_playbook": narr,
        "adaptive_rule": sigma,
        "execution_trace": final_state.get("execution_trace", []),
        "human_approval_required": True,
        "completed_agents": [
            "Provenance & Triage Agent (FR-4)",
            "Blast-Radius & Look-Ahead Agent (FR-6)",
            "Narrative & Playbook Agent (Bonus B-2)",
            "Adaptive Rule Authoring Agent (Bonus B-4)"
        ]
    }
