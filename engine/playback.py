"""
Temporal Attack Playback Engine (Chat Feature 4)
Generates chronological time-lapse frames for an incident.
Enables UI playback sliders to animate attack progression step-by-step
with nodes and edges lighting up red dynamically.
"""

from typing import Dict, List, Any


class PlaybackEngine:
    def __init__(self):
        pass

    def generate_timeline_playback(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds chronological animation frames for time-lapse attack playback.
        """
        timeline = incident.get("timeline", [])
        if not timeline:
            return {"frames": [], "total_frames": 0}

        frames = []
        cumulative_nodes = set()
        cumulative_edges = []

        for idx, step in enumerate(timeline):
            src = step.get("src")
            dst = step.get("dst")
            edge_id = f"edge_{idx}"
            cumulative_nodes.add(src)
            cumulative_nodes.add(dst)
            cumulative_edges.append(edge_id)

            tech_name = step.get("technique_name", "Attack Action")
            stage = step.get("kill_chain_stage", "Execution")
            raw_count = step.get("raw_alert_count", 1)
            sig = step.get("signature", "Alert")

            caption = f"Step {idx+1}: {src} -> {dst} ({tech_name}) [{raw_count:,} raw events]"

            frames.append({
                "frame_index": idx,
                "timestamp": step.get("timestamp"),
                "caption": caption,
                "current_kill_chain_stage": stage,
                "active_edge": {
                    "id": edge_id,
                    "source": src,
                    "target": dst,
                    "technique": step.get("technique_id"),
                    "technique_name": tech_name,
                    "signature": sig,
                    "raw_count": raw_count
                },
                "cumulative_nodes": sorted(list(cumulative_nodes)),
                "cumulative_edges": list(cumulative_edges)
            })

        return {
            "incident_id": incident.get("id"),
            "total_frames": len(frames),
            "start_time": incident.get("start_time"),
            "end_time": incident.get("end_time"),
            "frames": frames
        }

