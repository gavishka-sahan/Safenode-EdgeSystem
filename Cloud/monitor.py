#!/usr/bin/env python3
"""
Safenode Edge Monitor — CLI dashboard for cloud_data_storage
Reads detection results, health, features, and logs. Auto-refreshes every 5s.
Usage: python3 monitor.py [path/to/cloud_data_storage]
"""

import os
import sys
import json
import glob
import time
import shutil
from datetime import datetime

# ── ANSI colours ──────────────────────────────────────────────────────────────
R = "\033[0m"           # reset
BOLD = "\033[1m"
DIM = "\033[2m"

BLK = "\033[30m"
RED = "\033[91m"
GRN = "\033[92m"
YLW = "\033[93m"
BLU = "\033[94m"
MAG = "\033[95m"
CYN = "\033[96m"
WHT = "\033[97m"

BG_RED = "\033[41m"
BG_GRN = "\033[42m"
BG_YLW = "\033[43m"
BG_BLU = "\033[44m"
BG_MAG = "\033[45m"
BG_CYN = "\033[46m"
BG_GRY = "\033[100m"

REFRESH_INTERVAL = 5   # seconds
MAX_DETECTIONS = 8   # rows to show in detection table
MAX_LOG_LINES = 6   # lines to show from system_logs.log


# ── helpers ───────────────────────────────────────────────────────────────────

def cols():
    return shutil.get_terminal_size((120, 40)).columns


def hr(char="─", colour=DIM):
    return f"{colour}{char * cols()}{R}"


def badge(text, bg, fg=BLK):
    return f"{BOLD}{bg}{fg} {text} {R}"


def threat_colour(attack_type):
    t = attack_type.lower()
    if "mirai" in t:
        return MAG
    if "dos" in t or "ddos" in t or "flood" in t:
        return RED
    if "replay" in t:
        return YLW
    if "spoof" in t or "sniff" in t:
        return CYN
    if "normal" in t or "benign" in t or t == "none":
        return GRN
    return WHT


def severity_badge(sev):
    s = sev.lower()
    if s == "high":
        return badge("HIGH", BG_RED, WHT)
    if s == "medium":
        return badge("MED", BG_YLW, BLK)
    if s == "normal":
        return badge("OK", BG_GRN, BLK)
    return badge(sev.upper(), BG_GRY, WHT)


def fmt_ts(raw):
    """20260416_195458_328530 → 19:54:58"""
    try:
        return datetime.strptime(raw[:15], "%Y%m%d_%H%M%S").strftime("%H:%M:%S")
    except Exception:
        return raw[:15]


def fmt_iso(raw):
    """2026-04-16T19:44:18.995752 → 19:44:18"""
    try:
        return datetime.fromisoformat(raw).strftime("%H:%M:%S")
    except Exception:
        return str(raw)[:19]


def bar(value, total=100, width=20, colour=GRN):
    filled = int(width * min(value, total) / total)
    b = "█" * filled + "░" * (width - filled)
    pct = f"{value:.1f}%"
    return f"{colour}{b}{R} {DIM}{pct}{R}"


def pct_colour(v):
    if v >= 85:
        return RED
    if v >= 60:
        return YLW
    return GRN


def newest_files(directory, pattern, n=1):
    files = sorted(glob.glob(os.path.join(directory, pattern)), key=os.path.getmtime, reverse=True)
    return files[:n]


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def clear():
    print("\033[2J\033[H", end="")


# ── section renderers ─────────────────────────────────────────────────────────

def render_header(data_dir, now):
    w = cols()
    title = "  ◈  SAFENODE EDGE MONITOR"
    ts = f"refreshed {now.strftime('%H:%M:%S')}  "
    pad = w - len(title) - len(ts)
    print(f"{BOLD}{BG_BLU}{WHT}{title}{' ' * max(pad, 1)}{DIM}{ts}{R}")
    print(f"{DIM}  {data_dir}{R}")


def render_health(data_dir):
    print(f"\n{BOLD}{CYN}  SYSTEM HEALTH{R}  {DIM}(edge & extractor){R}")
    print(hr())

    edge_files = newest_files(data_dir, "health/*_edge_health.json")
    ext_files = newest_files(data_dir, "health/*_extractor_health.json")

    edge = load_json(edge_files[0]) if edge_files else {}
    ext = load_json(ext_files[0]) if ext_files else {}

    # ── edge column ──
    if edge:
        ts = fmt_iso(edge.get("timestamp", ""))
        conn = edge.get("mqtt", {}).get("connected", False)
        msgs = edge.get("mqtt", {}).get("messages_received", 0)
        bw = edge.get("bandwidth_bytes", 0)
        cl = edge.get("cloud", {})
        cloud_ok = cl.get("reachable", False)
        latency = cl.get("latency_ms")
        models = edge.get("models", {})

        conn_str = f"{GRN}● connected{R}" if conn else f"{RED}● disconnected{R}"
        cloud_str = f"{GRN}● reachable{R}" if cloud_ok else f"{RED}● unreachable{R}"
        lat_str = f"{DIM}{latency:.1f}ms{R}" if latency else f"{DIM}—{R}"

        print(f"  {BOLD}EdgeML Pi{R}  {DIM}@ {ts}{R}")
        print(f"    MQTT       {conn_str}   msgs={BOLD}{msgs}{R}")
        print(f"    Cloud      {cloud_str}  latency={lat_str}")
        print(f"    Bandwidth  {BOLD}{bw / 1e6:.1f} MB{R}")

        model_line = "    Models     "
        for name, present in models.items():
            icon = f"{GRN}✓{R}" if present else f"{RED}✗{R}"
            model_line += f"{icon}{DIM}{name}{R}  "
        print(model_line)
    else:
        print(f"  {BOLD}EdgeML Pi{R}  {RED}no data{R}")

    print()

    # ── extractor column ──
    if ext:
        hw = ext.get("hardware", {})
        sw = ext.get("software", {})
        ts = fmt_iso(ext.get("timestamp", ""))
        cpu = hw.get("cpu_usage_percent", 0)
        temp = hw.get("cpu_temperature_c")
        mem = hw.get("memory", {}).get("percent", 0)
        disk = hw.get("disk_usage_percent", 0)
        net = hw.get("network", {})
        rx = net.get("bytes_recv", 0) / 1e6
        tx = net.get("bytes_sent", 0) / 1e6
        up = hw.get("uptime_seconds", 0)
        sent = ext.get("sent_count", 0)

        temp_str = f"{YLW}{temp}°C{R}" if temp else f"{DIM}—{R}"
        uptime = f"{up // 3600}h {(up % 3600) // 60}m"

        print(f"  {BOLD}FlowExtractor Pi{R}  {DIM}@ {ts}{R}  uptime={DIM}{uptime}{R}  flows sent={BOLD}{sent}{R}")
        print(f"    CPU   {bar(cpu,  colour=pct_colour(cpu))}  {temp_str}")
        print(f"    RAM   {bar(mem,  colour=pct_colour(mem))}")
        print(f"    Disk  {bar(disk, colour=pct_colour(disk))}")
        print(f"    Net   {GRN}↓{R}{DIM}{rx:.1f}MB{R}  {BLU}↑{R}{DIM}{tx:.1f}MB{R}")

        svcs = sw.get("services", {})
        svc_line = "    Svcs  "
        for name, ok in svcs.items():
            icon = f"{GRN}✓{R}" if ok else f"{RED}✗{R}"
            svc_line += f"{icon}{DIM}{name}{R}  "
        print(svc_line)
    else:
        print(f"  {BOLD}FlowExtractor Pi{R}  {RED}no data{R}")


def render_detections(data_dir):
    print(f"\n{BOLD}{MAG}  RECENT DETECTIONS{R}")
    print(hr())

    files = sorted(
        glob.glob(os.path.join(data_dir, "detection_results/*_detection.json")),
        key=os.path.getmtime, reverse=True
    )[:MAX_DETECTIONS]

    if not files:
        print(f"  {DIM}no detection records yet{R}")
        return

    # header
    print(f"  {DIM}{'TIME':8}  {'SRC IP':17}  {'DST IP':22}  {'ATTACK':22}  {'CONF':6}  {'SEV':10}  THREAT{R}")
    print(f"  {DIM}{'─'*8}  {'─'*17}  {'─'*22}  {'─'*22}  {'─'*6}  {'─'*10}  {'─'*6}{R}")

    for path in files:
        d = load_json(path)
        ts = fmt_ts(d.get("timestamp", ""))
        src = d.get("source_ip", "?")[:17]
        dst = d.get("destination_ip", "?")[:22]
        attack = d.get("attack_type", "Unknown")
        conf = d.get("max_confidence", 0.0)
        sev = d.get("severity", "?")
        is_threat = d.get("is_threat", False)
        tc = threat_colour(attack)
        threat_icon = f"{RED}⚠ YES{R}" if is_threat else f"{GRN}✓ NO{R}"
        conf_str = f"{tc}{conf:.3f}{R}"

        print(f"  {DIM}{ts}{R}  {WHT}{src:<17}{R}  {DIM}{dst:<22}{R}  {tc}{attack:<22}{R}  {conf_str:<6}  {severity_badge(sev):<10}  {threat_icon}")


def render_features(data_dir):
    files = newest_files(data_dir, "json/*_features.json")
    if not files:
        return

    d = load_json(files[0])
    flow_id = d.get("flow_id", "?")
    src = d.get("src_ip", "?")
    dst = d.get("dst_ip", "?")
    ts = fmt_ts(d.get("timestamp") or os.path.basename(files[0])[:23])
    features = d.get("features", {})

    print(f"\n{BOLD}{BLU}  LATEST FLOW FEATURES{R}  {DIM}(27 cloud features){R}")
    print(hr())
    print(f"  {DIM}flow   {R}{WHT}{flow_id}{R}")
    print(f"  {DIM}src    {R}{WHT}{src}{R}   {DIM}dst {R}{WHT}{dst}{R}   {DIM}@ {ts}{R}")

    # show key features in a compact grid
    KEY = [
        ("flow_duration",   "duration"),
        ("packet_count",    "pkts"),
        ("byte_count",      "bytes"),
        ("packets_per_sec", "pkt/s"),
        ("bytes_per_sec",   "byt/s"),
        ("avg_packet_size", "avg_pkt"),
        ("syn_flag_count",  "SYN"),
        ("ack_flag_count",  "ACK"),
        ("rst_flag_count",  "RST"),
        ("ttl_value",       "TTL"),
        ("avg_iat",         "IAT avg"),
        ("max_iat",         "IAT max"),
    ]
    line = "  "
    for key, label in KEY:
        val = features.get(key, 0)
        val_str = f"{val:.2f}" if isinstance(val, float) else str(val)
        entry = f"{DIM}{label}={R}{CYN}{val_str}{R}  "
        line += entry
        if len(line) > cols() - 10:
            print(line)
            line = "  "
    if line.strip():
        print(line)


def render_logs(data_dir):
    log_file = os.path.join(data_dir, "logs", "system_logs.log")
    if not os.path.exists(log_file):
        return

    with open(log_file) as f:
        lines = [ln.rstrip() for ln in f.readlines() if ln.strip()]

    if not lines:
        return

    print(f"\n{BOLD}{YLW}  SYSTEM LOGS{R}  {DIM}(last {MAX_LOG_LINES} lines){R}")
    print(hr())

    for line in lines[-MAX_LOG_LINES:]:
        if "ERROR" in line:
            col = RED
        elif "WARNING" in line or "WARN" in line:
            col = YLW
        elif "INFO" in line:
            col = DIM
        else:
            col = DIM
        print(f"  {col}{line[:cols() - 4]}{R}")


def render_summary(data_dir):
    det_files = glob.glob(os.path.join(data_dir, "detection_results/*_detection.json"))
    feat_files = glob.glob(os.path.join(data_dir, "json/*_features.json"))
    health_files = glob.glob(os.path.join(data_dir, "health/*.json"))

    threats = sum(1 for p in det_files if load_json(p).get("is_threat", False))
    total = len(det_files)

    print(f"\n{BOLD}{WHT}  TOTALS{R}  {DIM}(files on disk){R}")
    print(hr())
    print(
        f"  detections={BOLD}{total}{R}  "
        f"threats={RED if threats else GRN}{BOLD}{threats}{R}  "
        f"features={BOLD}{len(feat_files)}{R}  "
        f"health={BOLD}{len(health_files)}{R}"
    )


# ── main loop ─────────────────────────────────────────────────────────────────

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        data_dir = os.path.abspath(sys.argv[1])
    else:
        data_dir = os.path.join(script_dir, "cloud_data_storage")

    if not os.path.isdir(data_dir):
        print(f"ERROR: directory not found: {data_dir}")
        sys.exit(1)

    print(f"Monitoring {data_dir}  (Ctrl+C to stop)")
    time.sleep(0.5)

    try:
        while True:
            now = datetime.now()
            clear()
            render_header(data_dir, now)
            render_health(data_dir)
            render_detections(data_dir)
            render_features(data_dir)
            render_logs(data_dir)
            render_summary(data_dir)
            print(f"\n{DIM}  next refresh in {REFRESH_INTERVAL}s — Ctrl+C to exit{R}")
            time.sleep(REFRESH_INTERVAL)
    except KeyboardInterrupt:
        print(f"\n{DIM}stopped.{R}")


if __name__ == "__main__":
    main()
