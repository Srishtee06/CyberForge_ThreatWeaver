"""
High-Performance Streaming Log Parser
Parses FortiGate UTM/Firewall key=value log records and streams them
into Parquet or memory batches without loading the entire 50GB file.
"""

import re
import os
import duckdb
from typing import Generator, List, Dict, Any, Optional

KV_REGEX = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

CORE_COLUMNS = [
    "timestamp",
    "eventtime",
    "type",
    "subtype",
    "level",
    "srcip",
    "srcport",
    "srcintf",
    "dstip",
    "dstport",
    "dstintf",
    "action",
    "service",
    "user",
    "status",
    "reason",
    "logdesc",
    "attack",
    "severity",
    "virus",
    "catdesc",
    "hostname",
    "sentbyte",
    "rcvdbyte"
]


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single FortiGate key=value log line.
    """
    if not line:
        return None
    matches = KV_REGEX.findall(line)
    if not matches:
        return None
    
    raw = {k: (v1 if v1 else v2) for k, v1, v2 in matches}
    
    # Construct unified timestamp
    date_str = raw.get("date", "")
    time_str = raw.get("time", "")
    ts = f"{date_str} {time_str}".strip() if date_str and time_str else None

    try:
        sb = int(raw.get("sentbyte", 0)) if raw.get("sentbyte") else 0
    except (ValueError, TypeError):
        sb = 0

    try:
        rb = int(raw.get("rcvdbyte", 0)) if raw.get("rcvdbyte") else 0
    except (ValueError, TypeError):
        rb = 0

    return {
        "timestamp": ts,
        "eventtime": raw.get("eventtime"),
        "type": raw.get("type"),
        "subtype": raw.get("subtype"),
        "level": raw.get("level"),
        "srcip": raw.get("srcip"),
        "srcport": raw.get("srcport"),
        "srcintf": raw.get("srcintf"),
        "dstip": raw.get("dstip"),
        "dstport": raw.get("dstport"),
        "dstintf": raw.get("dstintf"),
        "action": raw.get("action"),
        "service": raw.get("service"),
        "user": raw.get("user"),
        "status": raw.get("status"),
        "reason": raw.get("reason"),
        "logdesc": raw.get("logdesc"),
        "attack": raw.get("attack"),
        "severity": raw.get("severity"),
        "virus": raw.get("virus"),
        "catdesc": raw.get("catdesc"),
        "hostname": raw.get("hostname"),
        "sentbyte": sb,
        "rcvdbyte": rb
    }


def stream_log_batches(file_path: str, batch_size: int = 100000) -> Generator[List[Dict[str, Any]], None, None]:
    """
    Generator yielding batches of parsed records from disk, ensuring out-of-core memory safety.
    """
    batch = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            rec = parse_log_line(line)
            if rec:
                batch.append(rec)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
        if batch:
            yield batch

