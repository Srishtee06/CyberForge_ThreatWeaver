"""
ThreatWeaver LangGraph State Definitions
Typed shared state for the 4-Agent SOC Investigation Architecture.
"""

from typing import TypedDict, List, Dict, Any, Optional

class ProvenanceResult(TypedDict, total=False):
    agent: str
    incident_id: str
    verdict: str  # "true_positive" | "suspicious" | "insufficient_evidence" | "likely_benign"
    confidence: float
    verified_entities: List[str]
    entity_relationships: List[Dict[str, Any]]
    supporting_evidence: List[Dict[str, Any]]
    filtered_benign_events: List[Dict[str, Any]]
    missing_evidence: List[str]
    explanation: str
    execution_latency_ms: float

class FinancialExposure(TypedDict, total=False):
    value: Optional[float]
    currency: str
    calculation_basis: str

class BlastRadiusResult(TypedDict, total=False):
    agent: str
    incident_id: str
    compromised_accounts: List[str]
    credential_vectors: List[Dict[str, Any]]
    reachable_assets: List[Dict[str, Any]]
    crown_jewels_at_risk: List[Dict[str, Any]]
    lateral_paths: List[List[str]]
    financial_exposure: FinancialExposure
    minimum_isolation_plan: List[Dict[str, Any]]
    unreachable_assets: List[str]
    execution_latency_ms: float

class NarrativeResult(TypedDict, total=False):
    agent: str
    incident_id: str
    incident_title: str
    executive_summary: str
    attack_timeline: List[Dict[str, Any]]
    mitre_kill_chain: List[Dict[str, Any]]
    observed_stages: List[str]
    inferred_stages: List[str]
    recommended_actions: List[str]
    powershell_commands: List[str]
    firewall_commands: List[str]
    fortios_commands: List[str]
    rollback_instructions: List[str]
    execution_latency_ms: float

class SigmaResult(TypedDict, total=False):
    agent: str
    incident_id: str
    rule_id: str
    title: str
    status: str
    yaml_content: str
    is_valid: bool
    validation_errors: List[str]
    mitre_attack: List[str]
    indicators_extracted: Dict[str, Any]
    execution_latency_ms: float

class AgentTraceStep(TypedDict, total=False):
    agent: str
    status: str  # "pending" | "running" | "completed" | "partial" | "failed"
    task_received: str
    tool_selected: str
    tool_result: Any
    evidence_references: List[str]
    latency_ms: float
    timestamp: str

class InvestigationState(TypedDict, total=False):
    incident_id: str
    incident: Dict[str, Any]
    events: List[Dict[str, Any]]
    provenance_result: Optional[ProvenanceResult]
    blast_radius_result: Optional[BlastRadiusResult]
    narrative_result: Optional[NarrativeResult]
    sigma_result: Optional[SigmaResult]
    execution_trace: List[AgentTraceStep]
    errors: List[str]
    llm_enabled: bool
    approval_required: bool
    status: str

class ThreatWeaverState(TypedDict, total=False):
    incident_id: str
    incident: Dict[str, Any]
    events: List[Dict[str, Any]]
    investigation_findings: Dict[str, Any]
    attack_path_data: Dict[str, Any]
    threat_intel_data: Dict[str, Any]
    predictions_data: Dict[str, Any]
    defense_plan_data: Dict[str, Any]
    forensics_data: Dict[str, Any]
    governance_data: Dict[str, Any]
    completed_agents: List[str]
    iteration_count: int
    max_iterations: int
    next_step: str
    current_agent: str
    target_ips: List[str]
    needs_more_evidence: bool
    agent_trace: List[Dict[str, Any]]
    execution_time_ms: float
    status: str
    errors: List[str]
    provenance_result: Optional[ProvenanceResult]
    blast_radius_result: Optional[BlastRadiusResult]
    narrative_result: Optional[NarrativeResult]
    sigma_result: Optional[SigmaResult]
    execution_trace: List[AgentTraceStep]
    llm_enabled: bool
    approval_required: bool
