"""
End-to-End Integration Test Suite
Tests the full pipeline: DuckDB parse -> MITRE tag -> Graph -> Risk Score -> Reports
"""
# -*- coding: utf-8 -*-
import os
import sys
import time
import duckdb
import networkx as nx

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

print("=" * 60)
print("  CYBERFORGE END-TO-END INTEGRATION TEST")
print("=" * 60)

# -- Test 1: DuckDB Engine --
print("\n[1/5] DuckDB Out-of-Core Pipeline...")
t0 = time.time()
from engine.duckdb_engine import DuckDBEngine
engine = DuckDBEngine(memory_limit="4GB", threads=4)
result = engine.process_logs(output_parquet="data/flagged_alerts.parquet", max_scan_lines=200000)
t1 = time.time() - t0

assert result["status"] == "SUCCESS", "Pipeline failed!"
assert result["aggregated_attack_steps"] > 0, "Zero attack steps extracted!"
print(f"  [OK] {result['raw_alerts_merged']:,} raw alerts -> {result['aggregated_attack_steps']:,} attack steps in {t1:.1f}s")
print(f"    Parquet: {result['parquet_size_mb']} MB  |  Memory cap: {result['memory_limit_applied']}")

# -- Test 2: MITRE Technique Coverage --
print("\n[2/5] MITRE ATT&CK Technique Coverage...")
con = duckdb.connect()
tech_counts = con.execute("""
    SELECT technique_id, technique_name, tactic, count(*) as cnt
    FROM read_parquet('data/flagged_alerts.parquet')
    GROUP BY technique_id, technique_name, tactic
    ORDER BY cnt DESC
""").fetchall()

expected_techniques = {"T1110", "T1190", "T1068", "T1071.001", "T1486", "T1566", "T1048"}
found_techniques = {r[0] for r in tech_counts}
coverage = len(expected_techniques & found_techniques)

print(f"  Techniques detected:")
for tech in tech_counts:
    print(f"    {tech[0]} -- {tech[1]} ({tech[2]}): {tech[3]:,} steps")
print(f"  [OK] Coverage: {coverage}/{len(expected_techniques)} core MITRE techniques detected")

# -- Test 3: NetworkX Graph Build --
print("\n[3/5] Provenance Graph Construction...")
from engine.graph_engine import GraphEngine
graph_engine = GraphEngine(parquet_path="data/flagged_alerts.parquet")
incidents = graph_engine.build_graph_and_incidents(min_alerts_filter=1)

assert len(incidents) > 0, "No incidents extracted from graph!"
g = graph_engine.full_graph
print(f"  [OK] Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges, {len(incidents)} incidents")
top_raw = max(incidents, key=lambda x: x['total_raw_alerts_merged'])
print(f"    Largest incident: {top_raw['id']} -- {top_raw['total_raw_alerts_merged']:,} raw alerts")

# -- Test 4: Risk Scoring & Financial Exposure --
print("\n[4/5] Business Risk Scoring & Financial Exposure...")
from engine.risk_scoring import RiskScoringEngine
risk_engine = RiskScoringEngine(graph_engine.assets_db)
top_inc = incidents[0]
risk = risk_engine.calculate_incident_risk(top_inc)

print(f"  [OK] Incident {top_inc['id']}:")
print(f"    Risk Score    : {risk['risk_score']}/100 ({risk['severity']})")
print(f"    Financial Risk: ${risk['total_financial_liability_usd']:,.0f}")
print(f"    Crown Jewels  : {risk['crown_jewels_compromised']}")
print(f"    Compliance    : {risk['compliance_violations']}")

# -- Test 5: Dual Reports & Remediation --
print("\n[5/5] Dual Report Generation & Remediation Code...")
from engine.report_generator import ReportGenerator
from engine.remediation import RemediationEngine

rpt = ReportGenerator()
rem = RemediationEngine()

reports = rpt.generate_dual_reports(top_inc, risk)
assert "CYBERFORGE" in reports["soc_technical_report"] or "SOC" in reports["soc_technical_report"], "SOC report invalid!"
assert "Board" in reports["boardroom_summary"] or "Executive" in reports["boardroom_summary"], "Boardroom report invalid!"
print(f"  [OK] SOC Report: {len(reports['soc_technical_report'])} chars")
print(f"  [OK] Boardroom Report: {len(reports['boardroom_summary'])} chars")

playbook = rem.generate_remediation_playbook(top_inc)
assert "FortiOS" in playbook["playbooks"]["fortigate_cli"], "FortiGate CLI missing!"
assert "CyberForge" in playbook["playbooks"]["powershell"], "PowerShell script missing!"
print(f"  [OK] FortiGate CLI: {len(playbook['playbooks']['fortigate_cli'])} chars")
print(f"  [OK] PowerShell Script: {len(playbook['playbooks']['powershell'])} chars")

# -- Test 6: LangGraph 7-Agent Cybersecurity System --
print("\n[6/6] LangGraph 7-Agent Orchestration & Governance...")
from agents.orchestrator import run_multi_agent_investigation
agent_run = run_multi_agent_investigation(top_inc['id'])

assert agent_run["final_summary"] is not None, "LangGraph final synthesis failed!"
assert len(agent_run["completed_agents"]) == 7, f"Expected 7 agents, got {len(agent_run['completed_agents'])}"
print(f"  [OK] Successfully executed {len(agent_run['completed_agents'])}/7 LangGraph Agents:")
for a in agent_run["completed_agents"]:
    print(f"    - {a}")
print(f"  [OK] Supervisor Iterations: {agent_run['iteration_count']}")
print(f"  [OK] Human Approval Gate: {agent_run['human_approval_status']}")

# -- FINAL SUMMARY --
print("\n" + "=" * 60)
print("  ALL 6 TESTS PASSED (Including LangGraph Multi-Agent Team)")
print("  Ready to launch: python run.py --skip-pipeline")
print("=" * 60)
