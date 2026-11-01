"""
Business & Financial Risk Scoring Engine (Bonus B-1 + Chat Feature 3)
Calculates multi-factor risk scores (0-100) and quantifies business financial exposure,
regulatory penalties (PCI-DSS, GDPR, HIPAA), and asset loss based on proximity
to Crown Jewels like the PCI Payment DB and Domain Controller.
"""

from typing import Dict, List, Any


class RiskScoringEngine:
    def __init__(self, assets_db: Dict[str, Any]):
        self.assets_db = assets_db
        self.crown_jewels = assets_db.get("crown_jewels", [
            "10.10.20.198", "10.10.99.1", "10.10.99.10", "10.10.20.99"
        ])

    def calculate_incident_risk(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates holistic risk score and financial exposure for an incident.
        """
        score = 20  # Base score for any confirmed incident
        exposure_usd = 0
        regulatory_fines_usd = 0
        compliance_impacted = set()
        crown_jewels_hit = []

        incident_nodes = incident.get("nodes", [])
        techniques = set(incident.get("techniques", []))
        tactics = set(incident.get("tactics", []))
        stages = set(incident.get("kill_chain_stages", []))

        # Factor 1: Kill Chain Progression
        if "Action on Objectives" in stages or "Impact" in tactics or "Exfiltration" in tactics:
            score += 30
        elif "Command & Control" in stages or "Command and Control" in tactics:
            score += 20
        elif "Lateral Movement" in stages or "Lateral Movement" in tactics:
            score += 15
        elif "Exploitation" in stages or "Privilege Escalation" in tactics:
            score += 15
        elif "Installation" in stages or "Credential Access" in tactics:
            score += 10

        # Factor 2: Crown Jewel Proximity & Asset Values
        assets = self.assets_db.get("assets", {})
        for node in incident_nodes:
            if node in self.crown_jewels:
                crown_jewels_hit.append(node)
                score += 35
                if node in assets:
                    asset_info = assets[node]
                    exposure_usd += asset_info.get("asset_value_usd", 5000000)
                    regulatory_fines_usd += asset_info.get("potential_regulatory_fine_usd", 10000000)
                    for c in asset_info.get("compliance", []):
                        compliance_impacted.add(c)
            elif node in assets:
                asset_info = assets[node]
                exposure_usd += asset_info.get("asset_value_usd", 200000)
                for c in asset_info.get("compliance", []):
                    compliance_impacted.add(c)

        # Factor 3: High Volume Brute Force / Alert Explosion
        raw_count = incident.get("total_raw_alerts_merged", 1)
        if raw_count > 1000:
            score += 15
        elif raw_count > 100:
            score += 10

        # Cap score at 100
        final_score = min(max(int(score), 10), 100)

        # Severity categorization
        if final_score >= 85:
            severity = "CRITICAL"
        elif final_score >= 65:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Baseline baseline fines if critical infrastructure hit
        if crown_jewels_hit and regulatory_fines_usd == 0:
            regulatory_fines_usd = 10000000  # Default $10M baseline fine

        return {
            "risk_score": final_score,
            "severity": severity,
            "crown_jewels_compromised": crown_jewels_hit,
            "is_crown_jewel_threatened": len(crown_jewels_hit) > 0,
            "total_asset_exposure_usd": exposure_usd,
            "potential_regulatory_fines_usd": regulatory_fines_usd,
            "total_financial_liability_usd": exposure_usd + regulatory_fines_usd,
            "compliance_violations": sorted(list(compliance_impacted)),
            "risk_factors": [
                f"Kill Chain Depth: {', '.join(stages)}",
                f"Crown Jewels Hit: {len(crown_jewels_hit)}",
                f"Aggregated Telemetry: {raw_count:,} raw alerts merged"
            ]
        }

