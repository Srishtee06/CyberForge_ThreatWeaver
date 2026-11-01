"""
Look-Ahead Reachability Engine & "What-If" Blast Radius Containment Simulator
Predicts what the attacker could reach next (FR-6) and dynamically simulates
containment actions (isolating compromised nodes/accounts) to prove if attack
paths to Crown Jewels are severed or if alternative bypass routes exist.
"""

import networkx as nx
from typing import Dict, List, Any, Optional


class ReachabilityEngine:
    def __init__(self, crown_jewels: Optional[List[str]] = None):
        self.crown_jewels = crown_jewels or [
            "10.10.20.198",  # PCI Payment DB
            "10.10.99.1",    # Management Gateway
            "10.10.99.10",   # Active Directory Domain Controller
            "10.10.20.99"    # Corporate File Server FS-02
        ]

    def analyze_look_ahead(self, incident: Dict[str, Any], graph: nx.MultiDiGraph) -> Dict[str, Any]:
        """
        Analyzes reachable lateral movement paths from compromised nodes in the incident.
        """
        incident_nodes = set(incident.get("nodes", []))
        compromised_internal = [n for n in incident_nodes if n.startswith("10.10.")]

        reachable_assets = []
        crown_jewel_threats = []

        for node in compromised_internal:
            node_data = graph.nodes.get(node, {})
            # Look at neighbor nodes or potential subnet targets
            neighbors = list(graph.neighbors(node)) if node in graph else []
            for n in neighbors:
                if n not in incident_nodes:
                    asset_info = graph.nodes.get(n, {})
                    reachable_assets.append({
                        "from_node": node,
                        "target_node": n,
                        "hostname": asset_info.get("label", n),
                        "role": asset_info.get("role", "Internal Server"),
                        "zone": asset_info.get("zone", "internal"),
                        "criticality": asset_info.get("criticality", "MEDIUM"),
                        "asset_value_usd": asset_info.get("asset_value", 0)
                    })

            # Check distance to Crown Jewels
            for cj in self.crown_jewels:
                if node == cj:
                    crown_jewel_threats.append({
                        "crown_jewel": cj,
                        "status": "ALREADY_COMPROMISED",
                        "hops_away": 0,
                        "urgency": "CRITICAL"
                    })
                elif nx.has_path(graph, node, cj) if (node in graph and cj in graph) else False:
                    try:
                        path = nx.shortest_path(graph, node, cj)
                        crown_jewel_threats.append({
                            "crown_jewel": cj,
                            "from_node": node,
                            "hops_away": len(path) - 1,
                            "path": path,
                            "urgency": "IMMEDIATE" if len(path) <= 2 else "ELEVATED"
                        })
                    except Exception:
                        pass
                else:
                    # Subnet adjacency rule: if in same subnet or DMZ, reachable within 1-2 hops
                    cj_prefix = ".".join(cj.split(".")[:3])
                    node_prefix = ".".join(node.split(".")[:3])
                    if cj_prefix == node_prefix:
                        crown_jewel_threats.append({
                            "crown_jewel": cj,
                            "from_node": node,
                            "hops_away": 1,
                            "path": [node, cj],
                            "urgency": "IMMEDIATE"
                        })

        return {
            "compromised_nodes_count": len(compromised_internal),
            "next_reachable_assets": reachable_assets[:10],
            "crown_jewels_at_risk": crown_jewel_threats,
            "look_ahead_summary": f"Attacker has direct line-of-sight to {len(crown_jewel_threats)} critical assets from {len(compromised_internal)} compromised internal pivot(s)."
        }

    def simulate_containment(self, incident: Dict[str, Any], isolated_node: str, graph: nx.MultiDiGraph) -> Dict[str, Any]:
        """
        Simulates isolating a node (Blast Radius Containment Simulation).
        Recalculates graph connectivity to test whether attack paths to Crown Jewels are severed.
        """
        incident_nodes = set(incident.get("nodes", []))
        if isolated_node not in incident_nodes:
            return {"error": f"Node {isolated_node} is not part of this incident."}

        # Create a copy of the graph without the isolated node
        sim_graph = graph.copy()
        if isolated_node in sim_graph:
            sim_graph.remove_node(isolated_node)

        # Identify threat origins (external WAN IPs) in the incident
        threat_actors = [n for n in incident_nodes if not n.startswith("10.10.")]
        
        # Test connectivity to each crown jewel from threat actors
        active_paths = []
        severed_paths = []
        secured_crown_jewels = []

        for actor in threat_actors:
            for cj in self.crown_jewels:
                if cj == isolated_node:
                    severed_paths.append({
                        "threat_actor": actor,
                        "crown_jewel": cj,
                        "status": "ISOLATED_AND_CONTAINED"
                    })
                    secured_crown_jewels.append(cj)
                    continue

                if actor in sim_graph and cj in sim_graph and nx.has_path(sim_graph, actor, cj):
                    try:
                        p = nx.shortest_path(sim_graph, actor, cj)
                        active_paths.append({
                            "threat_actor": actor,
                            "crown_jewel": cj,
                            "bypass_route": p,
                            "hops": len(p) - 1
                        })
                    except Exception:
                        pass
                else:
                    severed_paths.append({
                        "threat_actor": actor,
                        "crown_jewel": cj,
                        "status": "ATTACK_PATH_SEVERED"
                    })
                    secured_crown_jewels.append(cj)

        is_attack_contained = len(active_paths) == 0
        reduction_pct = 100.0 if is_attack_contained else round((len(severed_paths) / (len(severed_paths) + len(active_paths))) * 100, 1)

        return {
            "isolated_node": isolated_node,
            "containment_successful": is_attack_contained,
            "blast_radius_reduction_percentage": reduction_pct,
            "active_bypass_routes": active_paths,
            "severed_attack_paths": severed_paths,
            "secured_crown_jewels": list(set(secured_crown_jewels)),
            "simulation_verdict": (
                f"CONTAINMENT SUCCESS: Isolating {isolated_node} completely severed all attack paths to Crown Jewels!"
                if is_attack_contained
                else f"PARTIAL CONTAINMENT: Isolating {isolated_node} severed {len(severed_paths)} route(s), but {len(active_paths)} alternative bypass route(s) still exist."
            )
        }

