#!/usr/bin/env python3
"""
cloud_data_analyzer.py — Safenode Cloud Data Offline Analyzer
Reads saved files from CloudSubscriber output directories and produces a
structured validation report without needing a live MQTT connection.

Directory layout expected (matches CloudSubscriber.py):
    /root/cloud_data_storage/
        detection_results/   *_detection.json
        health/              *_edge_health.json  *_extractor_health.json
        json/                *_features.json
        logs/                system_logs.log

Usage:
    python3 cloud_data_analyzer.py
    python3 cloud_data_analyzer.py --dir /root/cloud_data_storage
    python3 cloud_data_analyzer.py --sample 20          # analyze N files per category
    python3 cloud_data_analyzer.py --full               # show every issue found
"""

import os
import json
import argparse
import glob
from collections import Counter, defaultdict
from datetime import datetime

# ─── ANSI ─────────────────────────────────────────────────────────────────────
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
M    = "\033[95m"
DIM  = "\033[2m"
RST  = "\033[0m"
BOLD = "\033[1m"


def clr(text, colour):
    return f"{colour}{text}{RST}"


def section(title, colour=B):
    width = 64
    print(f"\n{colour}{BOLD}{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}{RST}")


def subsection(title, colour=C):
    print(f"\n{colour}{BOLD}── {title} ──{RST}")


def row(label, value, colour=None):
    c = colour or RST
    print(f"  {BOLD}{label:<32}{RST}{c}{value}{RST}")


def ok(label, value=""):
    print(f"  {G}✓{RST} {BOLD}{label:<30}{RST} {value}")


def warn(label, value=""):
    print(f"  {Y}⚠{RST} {BOLD}{label:<30}{RST} {Y}{value}{RST}")


def err(label, value=""):
    print(f"  {R}✗{RST} {BOLD}{label:<30}{RST} {R}{value}{RST}")


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def load_json_files(path, pattern, sample=None):
    files = sorted(glob.glob(os.path.join(path, pattern)))
    if sample and len(files) > sample:
        # take first, last, and middle sample
        step = max(1, len(files) // sample)
        files = files[::step][:sample]
    return files


def safe_load(filepath):
    try:
        with open(filepath) as f:
            return json.load(f), None
    except Exception as e:
        return None, str(e)


def map_classification(attack_type, is_threat):
    """Mirror CloudSubscriber.map_classification exactly."""
    if not is_threat:
        return "Normal"
    lower = str(attack_type).lower()
    if "mirai" in lower:
        return "Mirai"
    if "dos" in lower or "ddos" in lower or "flood" in lower:
        return "DOS"
    if "replay" in lower:
        return "Replay"
    return "Spoofing"


# ─── ANALYZERS ────────────────────────────────────────────────────────────────

def analyze_detections(det_dir, sample, full):
    section("DETECTION RESULTS  (detection_results/)", M)

    files = load_json_files(det_dir, "*_detection.json", sample)
    total = len(glob.glob(os.path.join(det_dir, "*_detection.json")))

    if not files:
        err("No files found", det_dir)
        return {}

    row("Total files on disk", str(total))
    row("Analyzing sample",    str(len(files)))

    issues = []
    attack_counts   = Counter()
    severity_counts = Counter()
    mitigation_counts = Counter()
    threat_count_vals = []
    confidence_vals = []
    latency_vals    = []
    missing_fields  = Counter()
    bad_confidence  = 0
    no_threats_but_threat = 0
    classification_mismatches = 0

    REQUIRED = ["timestamp", "source_ip", "destination_ip", "flow_id",
                "device_id", "is_threat", "threat_count", "max_confidence",
                "inference_time_ms", "attack_type", "threats", "severity",
                "mitigation", "edge_timestamp"]

    for fpath in files:
        data, load_err = safe_load(fpath)
        fname = os.path.basename(fpath)

        if load_err:
            issues.append(f"JSON error in {fname}: {load_err}")
            continue

        # Required field check
        for field in REQUIRED:
            if field not in data:
                missing_fields[field] += 1

        is_threat  = data.get("is_threat", False)
        attack_type = data.get("attack_type", "None")
        confidence  = data.get("max_confidence", None)
        latency     = data.get("inference_time_ms", None)
        threats     = data.get("threats", [])
        severity    = data.get("severity", "")
        mitigation  = data.get("mitigation", "")

        attack_counts[attack_type] += 1
        severity_counts[severity] += 1
        mitigation_counts[mitigation] += 1

        if isinstance(confidence, (int, float)):
            confidence_vals.append(confidence)
            if not (0.0 <= confidence <= 1.0):
                bad_confidence += 1
                if full:
                    issues.append(f"Confidence out of range ({confidence}) in {fname}")

        if isinstance(latency, (int, float)):
            latency_vals.append(latency)

        if isinstance(data.get("threat_count"), int):
            threat_count_vals.append(data["threat_count"])

        # is_threat=True but threats list empty
        if is_threat and isinstance(threats, list) and len(threats) == 0:
            no_threats_but_threat += 1
            if full:
                issues.append(f"is_threat=True but threats=[] in {fname}")

        # classification consistency
        expected_cls = map_classification(attack_type, is_threat)
        # detection_results doesn't store classification, but severity should match
        expected_sev = "High" if is_threat else "Normal"
        if severity != expected_sev:
            classification_mismatches += 1
            if full:
                issues.append(f"Severity mismatch: got={severity} expected={expected_sev} in {fname}")

    # Print summary
    subsection("Field Coverage")
    for field in REQUIRED:
        miss = missing_fields.get(field, 0)
        if miss == 0:
            ok(field, f"present in all {len(files)} files")
        elif miss < len(files):
            warn(field, f"missing in {miss}/{len(files)} files")
        else:
            err(field, f"MISSING in ALL files")

    subsection("Attack Type Distribution")
    for atype, count in attack_counts.most_common():
        pct = count / len(files) * 100
        col = R if atype not in ("None", "Unknown") else DIM
        print(f"  {col}{atype:<20}{RST}  {count:>5}  ({pct:.1f}%)")

    subsection("Severity Distribution")
    for sev, count in severity_counts.most_common():
        col = R if sev == "High" else G
        print(f"  {col}{sev:<20}{RST}  {count:>5}")

    subsection("Mitigation Distribution")
    for mit, count in mitigation_counts.most_common():
        print(f"  {mit:<20}  {count:>5}")

    subsection("Value Ranges")
    if confidence_vals:
        mn, mx, avg = min(confidence_vals), max(confidence_vals), sum(confidence_vals)/len(confidence_vals)
        col = R if bad_confidence > 0 else G
        print(f"  {col}confidence       min={mn:.4f}  max={mx:.4f}  avg={avg:.4f}  out-of-range={bad_confidence}{RST}")
    if latency_vals:
        mn, mx, avg = min(latency_vals), max(latency_vals), sum(latency_vals)/len(latency_vals)
        print(f"  latency_ms       min={mn:.2f}  max={mx:.2f}  avg={avg:.2f}")
    if threat_count_vals:
        print(f"  threat_count     min={min(threat_count_vals)}  max={max(threat_count_vals)}")

    subsection("Consistency Checks")
    if no_threats_but_threat == 0:
        ok("is_threat vs threats[]", "consistent across all files")
    else:
        warn("is_threat=True, threats=[]", f"found in {no_threats_but_threat} files")

    if classification_mismatches == 0:
        ok("severity vs is_threat", "consistent across all files")
    else:
        warn("severity/is_threat mismatch", f"{classification_mismatches} files")

    if issues and full:
        subsection("Issues Detail")
        for i in issues[:50]:
            print(f"  {Y}• {i}{RST}")

    return {"total": total, "sample": len(files), "attack_counts": dict(attack_counts)}


def analyze_health(health_dir, sample, full):
    section("HEALTH FILES  (health/)", B)

    edge_files = sorted(glob.glob(os.path.join(health_dir, "*_edge_health.json")))
    ext_files  = sorted(glob.glob(os.path.join(health_dir, "*_extractor_health.json")))

    row("Edge health files",      str(len(edge_files)))
    row("Extractor health files", str(len(ext_files)))

    if not edge_files and not ext_files:
        err("No health files found", health_dir)
        return

    # ── Edge health ──
    subsection("Edge Health Structure")
    sample_edge = edge_files[-min(sample, len(edge_files)):]
    edge_issues = 0
    for fpath in sample_edge:
        data, e = safe_load(fpath)
        if e:
            err(os.path.basename(fpath), e)
            edge_issues += 1
            continue
        # CloudSubscriber reads: data["mqtt"]["messages_received"], data["bandwidth_bytes"]
        mqtt_block = data.get("mqtt", {})
        bw = data.get("bandwidth_bytes")
        has_mqtt = isinstance(mqtt_block.get("messages_received"), (int, float))
        has_bw   = isinstance(bw, (int, float))
        if not has_mqtt or not has_bw:
            edge_issues += 1
            if full:
                warn(os.path.basename(fpath), f"mqtt.messages_received={mqtt_block.get('messages_received')}  bandwidth_bytes={bw}")

    if edge_issues == 0:
        ok("mqtt.messages_received", f"present in all {len(sample_edge)} sampled")
        ok("bandwidth_bytes",        f"present in all {len(sample_edge)} sampled")
    else:
        warn("Edge health issues", f"{edge_issues}/{len(sample_edge)} files have problems")

    # Show one example
    if edge_files:
        data, _ = safe_load(edge_files[-1])
        if data:
            print(f"\n  {DIM}Latest edge health keys: {list(data.keys())[:10]}{RST}")

    # ── Extractor health ──
    subsection("Extractor Health Structure")
    sample_ext = ext_files[-min(sample, len(ext_files)):]
    ext_issues = 0
    cpu_vals, mem_vals, disk_vals = [], [], []

    for fpath in sample_ext:
        data, e = safe_load(fpath)
        if e:
            err(os.path.basename(fpath), e)
            ext_issues += 1
            continue
        hw = data.get("hardware", {})
        cpu  = hw.get("cpu_usage_percent")
        mem  = hw.get("memory", {}).get("percent")
        disk = hw.get("disk_usage_percent")
        rx   = hw.get("network", {}).get("bytes_recv")
        tx   = hw.get("network", {}).get("bytes_sent")

        if any(v is None for v in [cpu, mem, disk, rx, tx]):
            ext_issues += 1
            if full:
                warn(os.path.basename(fpath), f"cpu={cpu} mem={mem} disk={disk} rx={rx} tx={tx}")

        if isinstance(cpu, (int, float)):  cpu_vals.append(cpu)
        if isinstance(mem, (int, float)):  mem_vals.append(mem)
        if isinstance(disk, (int, float)): disk_vals.append(disk)

    if ext_issues == 0:
        ok("hardware block", f"complete in all {len(sample_ext)} sampled")
    else:
        warn("Extractor health issues", f"{ext_issues}/{len(sample_ext)} files have problems")

    if cpu_vals:
        print(f"\n  {DIM}CPU    min={min(cpu_vals):.1f}%  max={max(cpu_vals):.1f}%  avg={sum(cpu_vals)/len(cpu_vals):.1f}%{RST}")
    if mem_vals:
        print(f"  {DIM}Memory min={min(mem_vals):.1f}%  max={max(mem_vals):.1f}%  avg={sum(mem_vals)/len(mem_vals):.1f}%{RST}")
    if disk_vals:
        print(f"  {DIM}Disk   min={min(disk_vals):.1f}%  max={max(disk_vals):.1f}%  avg={sum(disk_vals)/len(disk_vals):.1f}%{RST}")

    if ext_files:
        data, _ = safe_load(ext_files[-1])
        if data:
            print(f"\n  {DIM}Latest extractor health keys: {list(data.keys())[:10]}{RST}")


def analyze_features(json_dir, sample, full):
    section("FEATURE FILES  (json/)", C)

    files = load_json_files(json_dir, "*_features.json", sample)
    total = len(glob.glob(os.path.join(json_dir, "*_features.json")))

    if not files:
        err("No feature files found", json_dir)
        return

    row("Total files on disk", str(total))
    row("Analyzing sample",    str(len(files)))

    issues = []
    missing_top = Counter()
    feature_counts = []
    missing_traffic_fields = Counter()
    flow_ids_seen = set()
    duplicate_flow_ids = 0

    REQUIRED_TOP = ["flow_id", "src_ip", "dst_ip", "features"]
    # Fields CloudSubscriber reads when building /traffic-features
    TRAFFIC_FIELDS = ["byte_count", "avg_packet_size", "ttl_value"]

    for fpath in files:
        data, load_err = safe_load(fpath)
        fname = os.path.basename(fpath)

        if load_err:
            issues.append(f"JSON error in {fname}: {load_err}")
            continue

        for field in REQUIRED_TOP:
            if field not in data:
                missing_top[field] += 1

        flow_id = data.get("flow_id")
        if flow_id:
            if flow_id in flow_ids_seen:
                duplicate_flow_ids += 1
            flow_ids_seen.add(flow_id)

        features = data.get("features", {})
        if isinstance(features, dict):
            feature_counts.append(len(features))
            for tf in TRAFFIC_FIELDS:
                if tf not in features:
                    missing_traffic_fields[tf] += 1
        else:
            issues.append(f"features is not a dict in {fname}: {type(features)}")

    subsection("Top-Level Field Coverage")
    for field in REQUIRED_TOP:
        miss = missing_top.get(field, 0)
        if miss == 0:
            ok(field, f"present in all {len(files)} files")
        else:
            err(field, f"missing in {miss}/{len(files)} files")

    subsection("Feature Dict Contents")
    if feature_counts:
        mn, mx = min(feature_counts), max(feature_counts)
        avg = sum(feature_counts) / len(feature_counts)
        col = G if mn == mx else Y
        print(f"  {col}Feature count  min={mn}  max={mx}  avg={avg:.1f}{RST}")
        if mn != mx:
            warn("Inconsistent feature count", "different flows have different numbers of features")

    for tf in TRAFFIC_FIELDS:
        miss = missing_traffic_fields.get(tf, 0)
        label = f"features['{tf}']"
        if miss == 0:
            ok(label, f"present in all sampled")
        else:
            warn(label, f"missing in {miss}/{len(files)} — used by /traffic-features insert")

    subsection("Flow ID Checks")
    if duplicate_flow_ids == 0:
        ok("Duplicate flow_ids", "none in sample")
    else:
        warn("Duplicate flow_ids", f"{duplicate_flow_ids} duplicates found in sample")

    # Show structure of one file
    subsection("Sample File Structure")
    if files:
        data, _ = safe_load(files[-1])
        if data:
            print(f"  {DIM}Top keys: {list(data.keys())}{RST}")
            features = data.get("features", {})
            if isinstance(features, dict):
                sample_keys = list(features.keys())[:12]
                print(f"  {DIM}Feature keys (first 12): {sample_keys}{RST}")
                print(f"  {DIM}Total features: {len(features)}{RST}")

    if issues and full:
        subsection("Issues")
        for i in issues[:30]:
            print(f"  {Y}• {i}{RST}")


def analyze_logs(logs_dir):
    section("SYSTEM LOGS  (logs/)", DIM + Y)

    logfile = os.path.join(logs_dir, "system_logs.log")
    if not os.path.exists(logfile):
        warn("system_logs.log", "not found")
        return

    size_kb = os.path.getsize(logfile) / 1024
    row("File size", f"{size_kb:.1f} KB")

    with open(logfile) as f:
        lines = f.readlines()

    row("Total log lines", str(len(lines)))

    if not lines:
        warn("Log file", "empty")
        return

    # Show first and last few lines
    subsection("First 5 lines")
    for line in lines[:5]:
        print(f"  {DIM}{line.rstrip()}{RST}")

    subsection("Last 5 lines")
    for line in lines[-5:]:
        print(f"  {DIM}{line.rstrip()}{RST}")

    # Count error/warning indicators
    errors   = sum(1 for l in lines if "ERROR" in l or "error" in l)
    warnings = sum(1 for l in lines if "WARN" in l or "warn" in l)
    row("Lines with ERROR", str(errors), R if errors > 0 else G)
    row("Lines with WARN",  str(warnings), Y if warnings > 0 else G)


def analyze_correlation(det_dir, json_dir, sample):
    """Check that for every detection file there is a matching features file (same timestamp prefix)."""
    section("FEATURE ↔ ALERT CORRELATION  (flow_id matching)", Y)

    det_files  = sorted(glob.glob(os.path.join(det_dir,  "*_detection.json")))
    feat_files = sorted(glob.glob(os.path.join(json_dir, "*_features.json")))

    row("Detection files", str(len(det_files)))
    row("Feature files",   str(len(feat_files)))

    diff = len(det_files) - len(feat_files)
    if abs(diff) == 0:
        ok("Count match", "detection and feature counts are equal")
    elif abs(diff) <= 5:
        warn("Count mismatch", f"difference of {diff} (likely timing at capture boundary)")
    else:
        err("Count mismatch", f"difference of {diff} — some alerts have no features or vice versa")

    # Sample flow_id correlation
    sample_dets = det_files[-min(sample, len(det_files)):]
    det_flow_ids  = set()
    feat_flow_ids = set()

    for fpath in sample_dets:
        data, _ = safe_load(fpath)
        if data:
            fid = data.get("flow_id")
            if fid:
                det_flow_ids.add(fid)

    sample_feats = feat_files[-min(sample, len(feat_files)):]
    for fpath in sample_feats:
        data, _ = safe_load(fpath)
        if data:
            fid = data.get("flow_id")
            if fid:
                feat_flow_ids.add(fid)

    overlap = det_flow_ids & feat_flow_ids
    only_det  = det_flow_ids - feat_flow_ids
    only_feat = feat_flow_ids - det_flow_ids

    row("Sampled det flow_ids",  str(len(det_flow_ids)))
    row("Sampled feat flow_ids", str(len(feat_flow_ids)))

    if len(overlap) > 0:
        ok("flow_id overlap", f"{len(overlap)} flow_ids appear in both")
    else:
        warn("flow_id overlap", "0 matching flow_ids in sample — samples may not overlap in time")

    if only_det:
        warn("Alerts without features", f"{len(only_det)} flow_ids (pending_features pop missed)")
    if only_feat:
        warn("Features without alerts", f"{len(only_feat)} flow_ids (alert not yet received or missed)")


def print_summary(det_stats):
    section("SUMMARY", G)

    total_det = det_stats.get("total", 0)
    atk = det_stats.get("attack_counts", {})
    threats = {k: v for k, v in atk.items() if k not in ("None",)}
    benign  = atk.get("None", 0)

    row("Total detection records", str(total_det))
    if threats:
        for atype, count in sorted(threats.items(), key=lambda x: -x[1]):
            pct = count / det_stats.get("sample", 1) * 100
            print(f"  {R}  {atype:<22}{RST}  {count}  ({pct:.0f}% of sample)")
    if benign:
        print(f"  {G}  {'None (benign)':<22}{RST}  {benign}")

    print()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Safenode Cloud Data Offline Analyzer")
    parser.add_argument("--dir",    default="/root/cloud_data_storage", help="Base data directory")
    parser.add_argument("--sample", default=50, type=int, help="Max files to analyze per category (default: 50)")
    parser.add_argument("--full",   action="store_true", help="Print every individual issue found")
    args = parser.parse_args()

    base = args.dir
    det_dir    = os.path.join(base, "detection_results")
    health_dir = os.path.join(base, "health")
    json_dir   = os.path.join(base, "json")
    logs_dir   = os.path.join(base, "logs")

    print(f"\n{BOLD}{'═' * 64}")
    print(f"  Safenode Cloud Data Analyzer")
    print(f"  Base dir : {base}")
    print(f"  Sample   : {args.sample} files per category")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 64}{RST}")

    # Check dirs exist
    for d, name in [(det_dir, "detection_results"), (health_dir, "health"),
                    (json_dir, "json"), (logs_dir, "logs")]:
        if not os.path.isdir(d):
            warn(f"Directory missing", f"{d}  — skipping {name}")

    det_stats = analyze_detections(det_dir, args.sample, args.full)
    analyze_health(health_dir, args.sample, args.full)
    analyze_features(json_dir, args.sample, args.full)
    analyze_logs(logs_dir)
    analyze_correlation(det_dir, json_dir, args.sample)
    print_summary(det_stats)


if __name__ == "__main__":
    main()
