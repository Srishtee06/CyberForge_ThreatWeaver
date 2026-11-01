"""
Agent 4: Adaptive Rule Authoring Agent (Bonus B-4)
Extracts indicators from the active attack path to author detection logic.
Auto-populates a ready-to-save YAML/Sigma rule directly in the Detection Rules engine.
"""

import time
from typing import Dict, Any
from agents.state import InvestigationState, SigmaResult, AgentTraceStep
from agents.tools import (
    extractAttackIndicators,
    generateSigmaRule,
    validateSigmaRule,
    saveDetectionRule,
    get_incident_data
)

def adaptive_rule_node(state: InvestigationState) -> InvestigationState:
    t0 = time.perf_counter()
    inc_id = state.get("incident_id", "INC-12")
    incident = state.get("incident") or get_incident_data(inc_id)
    
    # 1. Deterministic indicator extraction
    indicators = extractAttackIndicators(inc_id)
    
    # 2. Generate Sigma Rule
    sigma_data = generateSigmaRule(inc_id)
    yaml_content = sigma_data.get("yaml_content") or sigma_data.get("yaml", "")
    
    # 3. Validate rule: returns (is_valid: bool, errors: List[str])
    is_valid, val_errors = validateSigmaRule(yaml_content)
    
    # 4. Save rule to config/rules/
    rule_dict = {
        "id": sigma_data.get("rule_id", f"SIGMA-{inc_id}"),
        "title": sigma_data.get("title", f"Detect Lateral Movement & Brute Force - {inc_id}"),
        "status": "testing",
        "description": f"Auto-generated adaptive rule from incident {inc_id}",
        "author": "ThreatWeaver Adaptive Rule Authoring Agent (Bonus B-4)",
        "mitre_attack": indicators.get("mitre_attack", ["T1078", "T1021.002", "T1110"]),
        "logsource": {"category": "process_creation", "product": "windows"},
        "yaml": yaml_content,
        "is_valid": is_valid
    }
    save_result = saveDetectionRule(rule_dict)
    
    latency = round((time.perf_counter() - t0) * 1000, 2)
    
    sigma_res: SigmaResult = {
        "agent": "Adaptive Rule Authoring Agent",
        "incident_id": inc_id,
        "rule_id": rule_dict["id"],
        "title": rule_dict["title"],
        "status": "saved" if save_result.get("saved") else "generated",
        "yaml_content": yaml_content,
        "is_valid": is_valid,
        "validation_errors": val_errors,
        "mitre_attack": rule_dict["mitre_attack"],
        "indicators_extracted": indicators,
        "execution_latency_ms": latency
    }
    
    trace_step: AgentTraceStep = {
        "agent": "Adaptive Rule Authoring Agent",
        "status": "completed",
        "task_received": f"Extract attack indicators and author valid Sigma detection rule for {inc_id}",
        "tool_selected": "extractAttackIndicators, generateSigmaRule, validateSigmaRule, saveDetectionRule",
        "tool_result": {
            "rule_id": rule_dict["id"],
            "title": rule_dict["title"],
            "is_valid": is_valid,
            "mitre_techniques": rule_dict["mitre_attack"],
            "indicators_found": len(indicators.get("suspicious_users", [])) + len(indicators.get("suspicious_ips", []))
        },
        "evidence_references": rule_dict["mitre_attack"],
        "latency_ms": latency,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    current_trace = list(state.get("execution_trace", []))
    current_trace.append(trace_step)
    
    return {
        **state,
        "sigma_result": sigma_res,
        "execution_trace": current_trace
    }
