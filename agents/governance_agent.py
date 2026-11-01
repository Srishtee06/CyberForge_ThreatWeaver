"""
Agent 7: Response Governance and Validation Agent
Validates proposed defense actions to guarantee safe, policy-compliant containment.
Checks operational impact against corporate change policies, flags actions requiring explicit human approval,
and logs immutable audit decisions.
"""

from typing import Dict, Any
from datetime import datetime
from agents.state import ThreatWeaverState
from agents.tools import (
    validate_response_plan,
    check_response_policy,
    request_human_approval,
    record_response_decision,
    verify_simulated_response
)

def governance_agent_node(state: ThreatWeaverState) -> ThreatWeaverState:
    """LangGraph node for Agent 7: Response Governance and Validation Agent."""
    incident_id = state.get("incident_id", "INC-001")
    defense_plan = state.get("defense_plan_data", {})
    
    proposed_actions = {
        "hosts_to_isolate": defense_plan.get("hosts_to_isolate", ["10.10.99.1"]),
        "accounts_to_revoke": defense_plan.get("accounts_to_revoke", ["adm_backup"]),
        "external_ips_to_block": defense_plan.get("external_ips_to_block", ["185.220.101.4"])
    }
    
    # 1. Execute tool calls: Policy checks, validation, approval determination
    validation = validate_response_plan(proposed_actions, incident_id)
    policy = check_response_policy(proposed_actions)
    verification = verify_simulated_response(proposed_actions)
    
    # Check if human approval is required
    requires_human = validation.get("requires_human_approval", False)
    approval_ticket = request_human_approval(proposed_actions) if requires_human else None
    
    # Record audit entry
    audit = record_response_decision({
        "decision": "VALIDATED_PENDING_APPROVAL" if requires_human else "VALIDATED_AUTOMATIC_ALLOWED",
        "operator": "LangGraph Supervisor / Governance Gate"
    })
    
    governance_data = {
        "agent_name": "Response Governance and Validation Agent",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "validated_plan": proposed_actions,
        "validation_result": validation,
        "policy_compliance_status": policy.get("compliance_check"),
        "requires_human_approval": requires_human,
        "human_approval_ticket": approval_ticket,
        "simulation_verification": verification,
        "audit_record": audit,
        "summary": (
            f"Governance review completed. Policy compliance: {policy.get('compliance_check')}. "
            f"Human approval required: {requires_human}. "
            f"Audit transaction {audit.get('audit_id')} recorded."
        )
    }
    
    history_entry = {
        "agent": "Response Governance and Validation Agent",
        "status": "COMPLETED",
        "tools_executed": [
            "validate_response_plan",
            "check_response_policy",
            "request_human_approval" if requires_human else "verify_simulated_response",
            "record_response_decision"
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output_summary": governance_data["summary"]
    }
    
    history = list(state.get("execution_history", []))
    history.append(history_entry)
    
    completed = list(state.get("completed_agents", []))
    if "Response Governance and Validation Agent" not in completed:
        completed.append("Response Governance and Validation Agent")
        
    return {
        **state,
        "governance_validation_data": governance_data,
        "human_approval_required": requires_human,
        "human_approval_status": "PENDING" if requires_human else "APPROVED",
        "human_approval_details": approval_ticket,
        "execution_history": history,
        "completed_agents": completed,
        "current_agent": "Response Governance and Validation Agent"
    }

