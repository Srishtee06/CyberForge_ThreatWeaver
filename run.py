#!/usr/bin/env python3
"""
CyberForge — Tactical Provenance Graph & Kill Chain Analysis Engine
Startup Entry Point

Usage:
  python run.py                     # Auto-detect log file, full pipeline + server
  python run.py --skip-pipeline     # Skip DuckDB scan, use existing flagged_alerts.parquet
  python run.py --host 0.0.0.0 --port 8000
"""

import argparse
import os
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

def main():
    parser = argparse.ArgumentParser(description="CyberForge Threat Intelligence Engine")
    parser.add_argument("--skip-pipeline", action="store_true", help="Skip DuckDB log scan, load existing parquet")
    parser.add_argument("--log-file", type=str, default=None, help="Path to log file")
    parser.add_argument("--max-lines", type=int, default=None, help="Limit lines for quick test runs")
    parser.add_argument("--memory", type=str, default="6GB", help="DuckDB memory cap (default: 6GB)")
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0"), help="Server host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)), help="Server port")
    args = parser.parse_args()

    # ── Phase 1: DuckDB Out-of-Core Processing ──────────────────────
    parquet_path = "data/flagged_alerts.parquet"

    if not args.skip_pipeline:
        print("\n" + "="*60)
        print("  CYBERFORGE — PHASE 1: OUT-OF-CORE STREAMING PIPELINE")
        print("  Engine : DuckDB (PRAGMA memory_limit='" + args.memory + "')")
        print("  Target : < 1 hour processing, < 8 GB peak RAM")
        print("="*60)

        from engine.duckdb_engine import DuckDBEngine
        engine = DuckDBEngine(memory_limit=args.memory, threads=4)

        t0 = time.time()
        res = engine.process_logs(
            log_path=args.log_file,
            output_parquet=parquet_path,
            max_scan_lines=args.max_lines
        )
        elapsed = time.time() - t0

        print(f"\n  ✓ Pipeline Complete in {elapsed:.1f}s")
        print(f"    Log File         : {res['log_file']}")
        print(f"    Raw Alerts Merged: {res['raw_alerts_merged']:,}")
        print(f"    Attack Steps     : {res['aggregated_attack_steps']:,}")
        print(f"    Parquet Size     : {res['parquet_size_mb']} MB (ZSTD compressed)")
        print(f"    Compression      : {res['compression_ratio']}")
        print(f"    Memory Cap Used  : {res['memory_limit_applied']}")
    else:
        if not os.path.exists(parquet_path):
            print(f"\n  Notice: No local {parquet_path} found. Operating in Cloud Standalone Mode.")
        else:
            print(f"\n  Skipping pipeline — using existing {parquet_path}")

    # ── Phase 2: Build NetworkX Provenance Graph ─────────────────────
    print("\n" + "="*60)
    print("  CYBERFORGE — PHASE 2: PROVENANCE GRAPH BUILD")
    print("  Engine: NetworkX Multi-Entity Directed Pivot Graph")
    print("="*60)

    if os.path.exists(parquet_path):
        from engine.graph_engine import GraphEngine
        from engine.risk_scoring import RiskScoringEngine
        
        graph_engine = GraphEngine(parquet_path=parquet_path)
        incidents = graph_engine.build_graph_and_incidents(min_alerts_filter=1)
        
        risk_engine = RiskScoringEngine(graph_engine.assets_db)
        
        print(f"\n  ✓ Graph Built:")
        print(f"    Total Nodes      : {graph_engine.full_graph.number_of_nodes():,}")
        print(f"    Total Edges      : {graph_engine.full_graph.number_of_edges():,}")
        print(f"    Incident Clusters: {len(incidents):,}")
        
        if incidents:
            top = incidents[0]
            risk = risk_engine.calculate_incident_risk(top)
            print(f"\n  ⚠  Top Incident [{top['id']}]:")
            print(f"    Risk Score       : {risk['risk_score']}/100 ({risk['severity']})")
            print(f"    Techniques       : {', '.join(top['techniques'])}")
            print(f"    Financial Exposure: ${risk['total_financial_liability_usd']:,.0f}")
            print(f"    Crown Jewels Hit : {len(risk['crown_jewels_compromised'])}")
    else:
        print("\n  ✓ Cloud Standalone Mode: Ready with pre-built incident clusters & LangGraph agents.")

    # ── Phase 3: Launch API + Web Console ───────────────────────────
    print("\n" + "="*60)
    print("  CYBERFORGE — PHASE 3: WEB CONSOLE & REST API")
    print(f"  URL: http://{args.host}:{args.port}")
    print(f"  API: http://{args.host}:{args.port}/api/incidents")
    print(f"  Docs: http://{args.host}:{args.port}/docs")
    print("="*60 + "\n")

    uvicorn.run("api.main:app", host=args.host, port=args.port, reload=False, log_level="info")


if __name__ == "__main__":
    main()

