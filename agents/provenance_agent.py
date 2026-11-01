"""
Agent 1: Provenance & Triage Agent (FR-4)
Verifies entity links across src_host, dst_host, and user, confirming why benign
background noise was filtered out and why this correlated cluster is a true positive.
"""

import time
from typing import Dict, Any
from agents.state import InvestigationState, ProvenanceResult, AgentTraceStep
from agents.tools import (
    verifyEntityLinks,
    classifyBenignNoise,
    calculateIncidentEvidenceScore,
    get_incident_data
)

def provenance_triage_node(state: InvestigationState) -> InvestigationState:
    t0 = time.perf_counter()
    inc_id = state.get("incident_id", "INC-12")
    incident = state.get("incident") or get_incident_data(inc_id)
    events = state.get("events") or incident.get("events", [])
    
    # 1. Execute deterministic tool calls
    link_data = verifyEntityLinks(inc_id)
    noise_data = classifyBenignNoise(inc_id)
    score = calculateIncidentEvidenceScore(inc_id)
    
    # Verdict logic (score is 0.0 to 1.0)
    score_100 = round(score * 100 if score <= 1.0 else score, 1)
    if score_100 >= 60:
        verdict = "true_positive"
    elif score_100 >= 30:
        verdict = "suspicious"
    else:
        verdict = "likely_benign"
        
    explanation = (
        f"Verified {len(link_data.get('verified_entities', []))} entities across "
        f"{len(link_data.get('causal_edges', []))} correlated events. "
        f"Filtered {len(noise_data)} benign noise events. "
        f"Incident evidence score is {score}/100, confirming this incident is a {verdict.replace('_', ' ').upper()}."
    )
    
    latency = round((time.perf_counter() - t0) * 1000, 2)
    
    provenance_res: ProvenanceResult = {
        "agent": "Provenance & Triage Agent",
        "incident_id": inc_id,
        "verdict": verdict,
        "confidence": score / 100.0,
        "verified_entities": link_data.get("verified_entities", []),
        "entity_relationships": link_data.get("causal_edges", []),
        "supporting_evidence": events[:5],
        "filtered_benign_events": noise_data[:5],
        "missing_evidence": link_data.get("missing_evidence", []),
        "explanation": explanation,
        "execution_latency_ms": latency
    }
    
    trace_step: AgentTraceStep = {
        "agent": "Provenance & Triage Agent",
        "status": "completed",
        "task_received": f"Verify causal provenance and filter benign noise for incident {inc_id}",
        "tool_selected": "verifyEntityLinks, classifyBenignNoise, calculateIncidentEvidenceScore",
        "tool_result": {
            "verdict": verdict,
            "evidence_score": score,
            "verified_entities_count": len(link_data.get("verified_entities", [])),
            "noise_filtered": len(noise_data)
        },
        "evidence_references": [e.get("technique_id", "T1078") for e in events[:4] if e.get("technique_id")],
        "latency_ms": latency,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    current_trace = list(state.get("execution_trace", []))
    current_trace.append(trace_step)
    
    return {
        **state,
        "incident": incident,
        "events": events,
        "provenance_result": provenance_res,
        "execution_trace": current_trace
    }
