"""
Dual-Mode Incident Report & Boardroom Translation Layer (Bonus B-2 + Chat Feature 5)
Generates synchronized reports for both audiences:
1. Technical SOC Forensic Deep Dive (MITRE techniques, IOCs, timestamps, raw log evidence)
2. Plain-English Boardroom Executive Summary (Business impact, bypassed controls, financial exposure)
"""

from typing import Dict, Any


class ReportGenerator:
    def __init__(self):
        pass

    def generate_dual_reports(self, incident: Dict[str, Any], risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produces both the SOC technical forensic report and the Boardroom executive briefing.
        """
        inc_id = incident.get("id", "INC-001")
        title = incident.get("title", "Attack Incident")
        start_time = incident.get("start_time", "N/A")
        end_time = incident.get("end_time", "N/A")
        raw_count = incident.get("total_raw_alerts_merged", 1)
        techniques = incident.get("techniques", [])
        tactics = incident.get("tactics", [])
        stages = incident.get("kill_chain_stages", [])
        users = incident.get("users_involved", [])
        nodes = incident.get("nodes", [])
        timeline = incident.get("timeline", [])

        risk_score = risk_data.get("risk_score", 75)
        severity = risk_data.get("severity", "HIGH")
        total_liability = risk_data.get("total_financial_liability_usd", 0)
        reg_fines = risk_data.get("potential_regulatory_fines_usd", 0)
        compliance = risk_data.get("compliance_violations", [])
        crown_jewels = risk_data.get("crown_jewels_compromised", [])

        # =========================================================================
        # 1. SOC Technical Forensic Deep Dive
        # =========================================================================
        soc_lines = [
            f"# SOC INCIDENT INVESTIGATION DOSSIER — {inc_id}",
            f"**Classification**: {severity} (Risk Score: {risk_score}/100)",
            f"**Observation Period**: {start_time} — {end_time}",
            f"**Telemetry Merging**: {raw_count:,} raw alerts compressed into {len(timeline)} attack steps",
            "",
            "## 1. Executive Kill Chain Progression",
            f"- **Observed ATT&CK Tactics**: {', '.join(tactics) if tactics else 'N/A'}",
            f"- **Kill Chain Stages**: {', '.join(stages) if stages else 'N/A'}",
            f"- **Tagged Techniques**: {', '.join(techniques) if techniques else 'N/A'}",
            f"- **Targeted Accounts**: {', '.join(users) if users else 'Service/System'}",
            "",
            "## 2. Forensic Attack Step Sequence",
            "| Step | Timestamp | Source -> Target | Technique | Signature | Raw Alerts |",
            "|---|---|---|---|---|:---:|"
        ]

        for s_idx, step in enumerate(timeline[:10], 1):
            src = step.get("src", "src")
            dst = step.get("dst", "dst")
            tech = step.get("technique_id", "T0000")
            sig = step.get("signature", "Alert")[:35]
            ts = step.get("timestamp", "")
            raw = step.get("raw_alert_count", 1)
            soc_lines.append(f"| {s_idx} | {ts} | `{src}` -> `{dst}` | **{tech}** | {sig} | {raw:,} |")

        soc_lines.extend([
            "",
            "## 3. Indicators of Compromise (IOCs)",
            f"- **Threat Actor IPs**: {', '.join([n for n in nodes if not n.startswith('10.10.')][:6])}",
            f"- **Internal Assets Compromised**: {', '.join([n for n in nodes if n.startswith('10.10.')][:6])}",
            f"- **Crown Jewels In Blast Radius**: {', '.join(crown_jewels) if crown_jewels else 'None Directly breached'}",
            "",
            "## 4. Root Cause & Correlation Mechanism",
            f"Aggregated out-of-core via DuckDB with strict 6 GB RAM ceilings. Correlated via NetworkX Multi-Entity Directed Pivot Graph.",
            f"Initial breach vector: {incident.get('initial_vector', 'External Network Infiltration')}"
        ])
        soc_report = "\n".join(soc_lines)

        # =========================================================================
        # 2. Boardroom Executive Translation Layer (Plain English)
        # =========================================================================
        boardroom_lines = [
            f"# EXECUTIVE BRIEFING: CYBER INCIDENT {inc_id}",
            f"**Prepared for**: Board of Directors & Executive Leadership Team",
            f"**Overall Threat Severity**: {severity} ({risk_score}/100)",
            f"**Estimated Financial Liability**: ${total_liability:,.2f}",
            "",
            "## What Happened (In Plain English)",
            f"An external adversary launched a targeted intrusion against our enterprise network. "
            f"Rather than a single loud alarm, the attackers generated over {raw_count:,} subtle activity bursts "
            f"scattered across our perimeter firewalls and internal servers.",
            "",
            f"The attack commenced at {start_time} with {incident.get('initial_vector', 'initial access probes')}. "
            f"The attacker attempted to bypass standard network boundaries and progress toward core enterprise databases.",
            "",
            "## Business & Financial Exposure",
            f"- **Potential Regulatory Fines**: Up to ${reg_fines:,.2f} under {', '.join(compliance) if compliance else 'Industry Cybersecurity Standards'}.",
            f"- **Critical Assets Targeted**: {len(crown_jewels)} high-value systems (including Domain Controllers and Payment Vaults).",
            f"- **Customer Trust & Brand Risk**: High — immediate public disclosure could trigger compliance audits if cardholder or PII data was accessed.",
            "",
            "## How Controls Were Circumvented",
            "Traditional security tools raised hundreds of thousands of disconnected alerts that overwhelmed the security team. "
            "Our automated Tactical Provenance Graph correlated these scattered footprints into a single cohesive story, "
            "exposing the attacker's trajectory before objectives were completed.",
            "",
            "## Strategic Recommendations for Leadership",
            "1. **Authorize Immediate Host Isolation**: Activate automated containment for the identified compromised endpoints.",
            "2. **Implement Blast Radius Hardening**: Revoke compromised admin credentials and isolate DMZ gateway routes.",
            "3. **Regulatory Notification Preparedness**: Stand by legal counsel regarding notification guidelines if forensics confirm data exfiltration."
        ]
        boardroom_summary = "\n".join(boardroom_lines)

        return {
            "incident_id": inc_id,
            "soc_technical_report": soc_report,
            "boardroom_summary": boardroom_summary
        }

