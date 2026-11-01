"""
Sigma-Style YAML Rule Compiler
Loads detection rules from config/rules/, embeds MITRE ATT&CK labels,
and compiles them into executable DuckDB SQL window queries.
"""

import os
import glob
import yaml
from typing import Dict, List, Any


class RuleCompiler:
    def __init__(self, rules_dir: str = "config/rules", mitre_file: str = "config/mitre_tactics.yaml"):
        self.rules_dir = rules_dir
        self.mitre_file = mitre_file
        self.rules: List[Dict[str, Any]] = []
        self.mitre_matrix: Dict[str, Any] = {}
        self.load_mitre_matrix()
        self.load_rules()

    def load_mitre_matrix(self):
        if os.path.exists(self.mitre_file):
            with open(self.mitre_file, "r", encoding="utf-8") as f:
                self.mitre_matrix = yaml.safe_load(f) or {}

    def load_rules(self) -> List[Dict[str, Any]]:
        self.rules = []
        rule_paths = glob.glob(os.path.join(self.rules_dir, "*.yaml"))
        for path in rule_paths:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rule_def = yaml.safe_load(f)
                    if rule_def and ("detection" in rule_def or "pattern" in rule_def or "mitre_id" in rule_def or "mitre" in rule_def):
                        rule_def["_file"] = path
                        self.rules.append(rule_def)
            except Exception as e:
                print(f"[!] Error loading rule {path}: {e}")
        return self.rules

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def compile_duckdb_filters(self) -> List[Dict[str, Any]]:
        """
        Compiles all loaded rules into SQL filter clauses and metadata attachments.
        """
        compiled = []
        for r in self.rules:
            mitre = r.get("mitre", {})
            tech_id = mitre.get("technique_id", "T0000")
            tech_name = mitre.get("technique_name", "Unknown")
            tactic = mitre.get("tactic", "Unknown")
            kill_chain = mitre.get("kill_chain_stage", "Unknown")
            severity = mitre.get("severity", "MEDIUM")

            for subrule in r.get("detection", {}).get("rules", []):
                name = subrule.get("name", "rule")
                sql = subrule.get("sql", "1=1")
                agg = subrule.get("aggregation", {})
                by = agg.get("by", ["srcip", "dstip"])
                window = agg.get("window_seconds", 60)
                threshold = agg.get("threshold", 1)

                compiled.append({
                    "rule_id": r.get("id"),
                    "title": r.get("title"),
                    "subrule_name": name,
                    "sql_condition": sql,
                    "by_fields": by,
                    "window_seconds": window,
                    "threshold": threshold,
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic,
                    "kill_chain_stage": kill_chain,
                    "severity": severity,
                    "remediation": r.get("remediation", {})
                })
        return compiled

