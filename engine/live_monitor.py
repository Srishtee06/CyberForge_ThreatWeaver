"""
Live Mode Streaming Engine (Bonus B-5)
Ingests new log lines in real-time, tags MITRE ATT&CK techniques,
and incrementally updates the attack graph within seconds.
"""

import time
from typing import Dict, Any, Optional, List
from engine.parser import parse_log_line
from engine.rule_compiler import RuleCompiler


class LiveMonitor:
    def __init__(self, graph_engine):
        self.graph_engine = graph_engine
        self.rule_compiler = RuleCompiler()
        self.buffered_events: List[Dict[str, Any]] = []

    def ingest_live_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses and classifies an incoming live log line, updating graph topology.
        """
        parsed = parse_log_line(line)
        if not parsed or not parsed.get("srcip") or not parsed.get("dstip"):
            return None

        # Check if suspicious
        attack = parsed.get("attack") or ""
        logdesc = parsed.get("logdesc") or ""
        catdesc = parsed.get("catdesc") or ""
        virus = parsed.get("virus") or ""

        is_suspicious = bool(attack or virus or ("Admin login failed" in logdesc) or ("Ransomware" in catdesc) or ("Botnet" in catdesc))
        if not is_suspicious:
            return None

        # Determine MITRE technique
        if "Log4j" in attack or "vCenter" in attack or "Citrix" in attack:
            tech_id = "T1190"
            tech_name = "Exploit Public-Facing Application"
            stage = "Weaponization & Delivery"
            tactic = "Initial Access"
        elif "Admin login failed" in logdesc or "Brute.Force" in attack:
            tech_id = "T1110"
            tech_name = "Brute Force"
            stage = "Installation"
            tactic = "Credential Access"
        elif "ZeroLogon" in attack or "Privilege.Escalation" in attack:
            tech_id = "T1068"
            tech_name = "Exploitation for Privilege Escalation"
            stage = "Exploitation"
            tactic = "Privilege Escalation"
        elif "SMB" in attack:
            tech_id = "T1021.002"
            tech_name = "SMB/Windows Admin Shares"
            stage = "Lateral Movement"
            tactic = "Lateral Movement"
        elif "Cobalt.Strike" in attack or "Mirai" in attack or "Botnet" in catdesc:
            tech_id = "T1071.001"
            tech_name = "Web Protocols (Cobalt Strike / C2 Beaconing)"
            stage = "Command & Control"
            tactic = "Command and Control"
        elif "Ransomware" in catdesc or virus:
            tech_id = "T1486"
            tech_name = "Data Encrypted for Impact (Ransomware)"
            stage = "Action on Objectives"
            tactic = "Impact"
        else:
            tech_id = "T1059"
            tech_name = "Command and Scripting Interpreter"
            stage = "Exploitation"
            tactic = "Execution"

        event = {
            "timestamp": parsed.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
            "srcip": parsed.get("srcip"),
            "dstip": parsed.get("dstip"),
            "user": parsed.get("user") or "unknown",
            "technique_id": tech_id,
            "technique_name": tech_name,
            "kill_chain_stage": stage,
            "tactic": tactic,
            "severity": parsed.get("severity") or "HIGH",
            "signature": attack or virus or catdesc or logdesc,
            "raw_alert_count": 1
        }

        # Add to graph
        src_asset = self.graph_engine.get_asset_info(event["srcip"])
        dst_asset = self.graph_engine.get_asset_info(event["dstip"])

        self.graph_engine.full_graph.add_node(
            event["srcip"],
            node_id=event["srcip"],
            label=src_asset["hostname"],
            zone=src_asset["zone"],
            role=src_asset["role"],
            criticality=src_asset["criticality"],
            asset_value=src_asset["asset_value_usd"],
            type="external" if src_asset["zone"] == "wan" else "internal"
        )

        self.graph_engine.full_graph.add_node(
            event["dstip"],
            node_id=event["dstip"],
            label=dst_asset["hostname"],
            zone=dst_asset["zone"],
            role=dst_asset["role"],
            criticality=dst_asset["criticality"],
            asset_value=dst_asset["asset_value_usd"],
            type="crown_jewel" if dst_asset["criticality"] in ("CRITICAL", "CROWN_JEWEL") else "internal"
        )

        self.graph_engine.full_graph.add_edge(
            event["srcip"],
            event["dstip"],
            timestamp=event["timestamp"],
            technique_id=event["technique_id"],
            technique_name=event["technique_name"],
            tactic=event["tactic"],
            kill_chain_stage=event["kill_chain_stage"],
            severity=event["severity"],
            signature=event["signature"],
            raw_alert_count=1,
            user=event["user"]
        )

        self.buffered_events.append(event)
        return event

