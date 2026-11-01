"""
Tactical Provenance Graph Engine (NetworkX)
Builds multi-entity directed pivot graphs linking Users, Hosts, IPs and Crown Jewels.
Rebuilds full attack paths, isolates connected incident clusters,
and tracks raw alerts merged per incident.
"""

import os
import yaml
import networkx as nx
import duckdb
from typing import Dict, List, Any, Optional


class GraphEngine:
    def __init__(self, assets_file: str = "config/assets.yaml", parquet_path: str = "data/flagged_alerts.parquet"):
        self.assets_file = assets_file
        self.parquet_path = parquet_path
        self.assets_db = self._load_assets()
        self.full_graph = nx.MultiDiGraph()
        self.incidents: List[Dict[str, Any]] = []

    def _load_assets(self) -> Dict[str, Any]:
        if os.path.exists(self.assets_file):
            with open(self.assets_file, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def get_asset_info(self, ip: str) -> Dict[str, Any]:
        """
        Enriches an IP with hostname, business role, zone, criticality, and asset value.
        """
        assets = self.assets_db.get("assets", {})
        if ip in assets:
            info = dict(assets[ip])
            info["ip"] = ip
            return info

        # Subnet matching
        if ip.startswith("10.10.99."):
            return {
                "ip": ip,
                "hostname": f"MGMT-SRV-{ip.split('.')[-1]}",
                "role": "Management & Infrastructure Server",
                "zone": "mgmt",
                "criticality": "HIGH",
                "asset_value_usd": 4000000,
                "compliance": ["SOC-2"]
            }
        elif ip.startswith("10.10.20."):
            return {
                "ip": ip,
                "hostname": f"DMZ-SRV-{ip.split('.')[-1]}",
                "role": "DMZ Application / Database Server",
                "zone": "dmz",
                "criticality": "HIGH",
                "asset_value_usd": 3500000,
                "compliance": ["PCI-DSS", "GDPR"]
            }
        elif ip.startswith("10.10.40."):
            return {
                "ip": ip,
                "hostname": f"HR-FIN-LAPTOP-{ip.split('.')[-1]}",
                "role": "HR & Financial Services Laptop",
                "zone": "internal4",
                "criticality": "MEDIUM",
                "asset_value_usd": 300000,
                "compliance": ["SOC-2"]
            }
        elif ip.startswith("10.10.10."):
            return {
                "ip": ip,
                "hostname": f"ENG-WS-{ip.split('.')[-1]}",
                "role": "Engineering Workstation",
                "zone": "internal1",
                "criticality": "MEDIUM",
                "asset_value_usd": 200000,
                "compliance": []
            }
        elif ip.startswith("10.10.50."):
            return {
                "ip": ip,
                "hostname": f"VENDOR-WS-{ip.split('.')[-1]}",
                "role": "Third-Party Contractor Terminal",
                "zone": "internal5",
                "criticality": "MEDIUM",
                "asset_value_usd": 150000,
                "compliance": []
            }
        elif ip.startswith("10.10.30."):
            return {
                "ip": ip,
                "hostname": f"OPS-WS-{ip.split('.')[-1]}",
                "role": "Operations & Logistics Host",
                "zone": "internal3",
                "criticality": "MEDIUM",
                "asset_value_usd": 200000,
                "compliance": []
            }
        else:
            return {
                "ip": ip,
                "hostname": f"EXT-{ip.replace('.', '-')}",
                "role": "External / Threat Actor IP",
                "zone": "wan",
                "criticality": "LOW",
                "asset_value_usd": 0,
                "compliance": []
            }

    def build_graph_and_incidents(self, min_alerts_filter: int = 1) -> List[Dict[str, Any]]:
        """
        Loads flagged_alerts.parquet and constructs the MultiDiGraph and correlated Incidents.
        """
        if not os.path.exists(self.parquet_path):
            return []

        con = duckdb.connect()
        query = f"""
        SELECT 
            first_seen,
            last_seen,
            srcip,
            dstip,
            srcintf,
            dstintf,
            service,
            user,
            technique_id,
            technique_name,
            tactic,
            kill_chain_stage,
            severity,
            attack_signature,
            raw_alert_count,
            total_sentbyte,
            sample_evidence
        FROM read_parquet('{self.parquet_path.replace(chr(92), "/")}')
        WHERE raw_alert_count >= {min_alerts_filter}
        ORDER BY first_seen ASC
        """
        rows = con.execute(query).fetchall()
        con.close()

        self.full_graph = nx.MultiDiGraph()

        # Step 1: Add nodes and directed edges to MultiDiGraph
        for row in rows:
            (first_seen, last_seen, srcip, dstip, srcintf, dstintf, service,
             user, technique_id, technique_name, tactic, kill_chain_stage,
             severity, attack_sig, raw_count, sentbyte, sample_evidence) = row

            src_asset = self.get_asset_info(srcip)
            dst_asset = self.get_asset_info(dstip)

            # Add source node
            self.full_graph.add_node(
                srcip,
                node_id=srcip,
                label=src_asset["hostname"],
                zone=src_asset["zone"],
                role=src_asset["role"],
                criticality=src_asset["criticality"],
                asset_value=src_asset["asset_value_usd"],
                compliance=src_asset["compliance"],
                type="external" if src_asset["zone"] == "wan" else "internal"
            )

            # Add destination node
            self.full_graph.add_node(
                dstip,
                node_id=dstip,
                label=dst_asset["hostname"],
                zone=dst_asset["zone"],
                role=dst_asset["role"],
                criticality=dst_asset["criticality"],
                asset_value=dst_asset["asset_value_usd"],
                compliance=dst_asset["compliance"],
                type="crown_jewel" if dst_asset["criticality"] in ("CRITICAL", "CROWN_JEWEL") else "internal"
            )

            # Add directed edge
            self.full_graph.add_edge(
                srcip,
                dstip,
                timestamp=str(first_seen),
                last_seen=str(last_seen),
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                kill_chain_stage=kill_chain_stage,
                severity=severity,
                signature=attack_sig,
                raw_alert_count=raw_count,
                user=user,
                service=service,
                sentbyte=sentbyte,
                evidence=str(sample_evidence)[:150]
            )

        # Step 2: Extract Connected Incident Clusters
        # Convert to undirected graph for connected component partitioning
        undirected = self.full_graph.to_undirected()
        components = list(nx.connected_components(undirected))

        incidents_list = []
        for idx, comp in enumerate(components):
            subgraph = self.full_graph.subgraph(comp)
            edges_data = []
            for u, v, k, data in subgraph.edges(keys=True, data=True):
                edges_data.append({"src": u, "dst": v, **data})

            if not edges_data:
                continue

            # Sort edges chronologically
            edges_data.sort(key=lambda x: x.get("timestamp", ""))

            total_raw_alerts = sum(e.get("raw_alert_count", 1) for e in edges_data)
            unique_techniques = sorted(list(set(e.get("technique_id") for e in edges_data)))
            unique_tactics = sorted(list(set(e.get("tactic") for e in edges_data)))
            unique_stages = sorted(list(set(e.get("kill_chain_stage") for e in edges_data)))
            users_involved = sorted(list(set(e.get("user") for e in edges_data if e.get("user") != "unknown")))

            # Classify compromised crown jewels
            crown_jewels_hit = [
                n for n in comp 
                if self.full_graph.nodes[n].get("criticality") in ("CRITICAL", "CROWN_JEWEL")
            ]

            first_event = edges_data[0]
            last_event = edges_data[-1]

            inc_id = f"INC-{idx+1:03d}"
            
            # Format Cytoscape graph nodes and edges
            cyto_nodes = []
            for n in comp:
                ndata = self.full_graph.nodes[n]
                cyto_nodes.append({
                    "data": {
                        "id": n,
                        "label": ndata.get("label", n),
                        "role": ndata.get("role", "Host"),
                        "zone": ndata.get("zone", "internal"),
                        "criticality": ndata.get("criticality", "MEDIUM"),
                        "asset_value": ndata.get("asset_value", 0),
                        "type": ndata.get("type", "internal"),
                        "isolated": False
                    }
                })

            cyto_edges = []
            for e_idx, e in enumerate(edges_data):
                cyto_edges.append({
                    "data": {
                        "id": f"e_{idx}_{e_idx}",
                        "source": e["src"],
                        "target": e["dst"],
                        "technique": e["technique_id"],
                        "technique_name": e["technique_name"],
                        "tactic": e["tactic"],
                        "kill_chain_stage": e["kill_chain_stage"],
                        "signature": e["signature"],
                        "raw_count": e["raw_alert_count"],
                        "timestamp": e["timestamp"],
                        "severity": e["severity"]
                    }
                })

            incident = {
                "id": inc_id,
                "title": f"{first_event.get('technique_name', 'Attack')} campaign targeting {len(comp)} nodes",
                "start_time": first_event.get("timestamp"),
                "end_time": last_event.get("timestamp"),
                "node_count": len(comp),
                "edge_count": len(edges_data),
                "total_raw_alerts_merged": total_raw_alerts,
                "initial_vector": f"{first_event.get('src')} -> {first_event.get('dst')} via {first_event.get('signature')}",
                "techniques": unique_techniques,
                "tactics": unique_tactics,
                "kill_chain_stages": unique_stages,
                "users_involved": users_involved,
                "crown_jewels_targeted": crown_jewels_hit,
                "nodes": list(comp),
                "timeline": edges_data,
                "graph": {
                    "nodes": cyto_nodes,
                    "edges": cyto_edges
                }
            }
            incidents_list.append(incident)

        self.incidents = incidents_list
        return self.incidents

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        for inc in self.incidents:
            if inc["id"] == incident_id:
                return inc
        return None

