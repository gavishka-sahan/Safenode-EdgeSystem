"""
Cisco WS-C3650-24TS Switch Poller + Isolation Executor
=======================================================
Polls a Cisco Catalyst 3650 switch via SSH, collects port data,
pushes to the IoT SOC Dashboard API, and executes VLAN isolation
commands when triggered from the dashboard.

Switch: Cisco WS-C3650-24TS (192.168.8.2)
API:    http://217.217.248.193/api/v1

Port Layout:
  Gi1/0/1  - Gi1/0/24  → Ports 1-24 (main access ports)
  Gi1/1/1  - Gi1/1/4   → Ports 25-28 (uplink module)

Requirements:
    pip install netmiko requests

Usage:
    python switch_poller.py
"""

import time
import re
import requests
import logging
from datetime import datetime, timezone
from netmiko import ConnectHandler

# ============================================================
# CONFIGURATION
# ============================================================

SWITCH_CONFIG = {
    "device_type": "cisco_ios",
    "host": "192.168.8.2",
    "username": "admin",
    "password": "admin",
    "secret": "admin",
    "timeout": 30,
    "session_timeout": 60,
}

API_CONFIG = {
    "base_url": "http://217.217.248.193/api/v1",
    "timeout": 10,
}

QUARANTINE_VLAN = 999
QUARANTINE_VLAN_NAME = "QUARANTINE"
POLL_INTERVAL = 5
DEBUG = True

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("poller")

# ============================================================
# SSH
# ============================================================


def connect_to_switch():
    try:
        log.info(f"Connecting to switch at {SWITCH_CONFIG['host']}...")
        conn = ConnectHandler(**SWITCH_CONFIG)
        conn.enable()
        log.info("Connected.")
        return conn
    except Exception as e:
        log.error(f"Connection failed: {e}")
        return None


def cmd(conn, command):
    try:
        return conn.send_command(command, read_timeout=20)
    except Exception as e:
        log.error(f"Command '{command}' failed: {e}")
        return ""


# ============================================================
# PARSERS — Cisco C3650 IOS-XE
# ============================================================


def parse_interfaces_status(output):
    """
    C3650 'show interfaces status' output:
    Port      Name               Status       Vlan       Duplex  Speed Type
    Gi1/0/1                      monitoring   1            auto a-1000 10/100/1000BaseTX
    Gi1/0/2                      connected    1          a-full a-1000 10/100/1000BaseTX
    Gi1/0/3                      notconnect   1            auto   auto 10/100/1000BaseTX
    Gi1/1/1                      notconnect   1            auto   auto unknown
    """
    ports = {}
    lines = output.strip().split("\n")

    for line in lines:
        if not line.strip() or ("Port" in line and "Name" in line) or "---" in line:
            continue

        # Get the port name (first word)
        match = re.match(r"^(\S+)", line)
        if not match:
            continue

        port_name = match.group(1)

        # Only process Gi and Te ports
        if not any(port_name.startswith(p) for p in ["Gi", "Te", "Fa"]):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        status_keywords = ["connected", "notconnect", "disabled", "err-disabled", "monitoring"]

        device_name = None
        status_raw = None
        vlan_raw = None
        speed_raw = None

        # Find which part is the status keyword
        for i, part in enumerate(parts):
            if part in status_keywords:
                if i == 1:
                    # No device name: Port Status Vlan Duplex Speed Type
                    device_name = None
                    status_raw = parts[1]
                    vlan_raw = parts[2] if len(parts) > 2 else "1"
                    speed_raw = parts[4] if len(parts) > 4 else "auto"
                elif i == 2:
                    # Has device name: Port Name Status Vlan Duplex Speed Type
                    device_name = parts[1]
                    status_raw = parts[2]
                    vlan_raw = parts[3] if len(parts) > 3 else "1"
                    speed_raw = parts[5] if len(parts) > 5 else "auto"
                elif i > 2:
                    # Multi-word device name
                    device_name = " ".join(parts[1:i])
                    status_raw = parts[i]
                    vlan_raw = parts[i + 1] if len(parts) > i + 1 else "1"
                    speed_raw = parts[i + 3] if len(parts) > i + 3 else "auto"
                break

        if not status_raw:
            continue

        port_number = extract_port_number(port_name)
        if port_number == 0:
            continue

        ports[port_name] = {
            "port_number": port_number,
            "port_name": port_name,
            "device_name": device_name,
            "status": map_port_status(status_raw),
            "vlan": parse_vlan(vlan_raw),
            "speed": parse_speed(speed_raw, port_name),
        }

        if DEBUG:
            log.info(f"  [PORT] {port_name} → num={port_number}, status={status_raw}, vlan={vlan_raw}, device={device_name}")

    return ports


def parse_interfaces_counters(output):
    """
    Parse 'show interfaces counters' for byte counts.
    """
    counters = {}
    lines = output.strip().split("\n")
    current_direction = None

    for line in lines:
        if "InOctets" in line:
            current_direction = "in"
            continue
        elif "OutOctets" in line:
            current_direction = "out"
            continue
        if not current_direction:
            continue

        match = re.match(r"(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", line.strip())
        if match:
            port_name = match.group(1)
            octets = int(match.group(2))
            if port_name not in counters:
                counters[port_name] = {"in_octets": 0, "out_octets": 0}
            if current_direction == "in":
                counters[port_name]["in_octets"] = octets
            else:
                counters[port_name]["out_octets"] = octets

    return counters


def parse_interfaces_errors(output):
    """
    Parse 'show interfaces counters errors' for error/drop counts.
    """
    errors = {}
    lines = output.strip().split("\n")

    for line in lines:
        match = re.match(r"(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", line.strip())
        if match:
            port_name = match.group(1)
            if any(port_name.startswith(p) for p in ["Gi", "Te", "Fa"]):
                total_errors = int(match.group(2)) + int(match.group(3)) + int(match.group(4)) + int(match.group(5))
                total_drops = int(match.group(7))
                errors[port_name] = {"errors": total_errors, "drops": total_drops}

    return errors


def parse_mac_address_table(output):
    """
    C3650 'show mac address-table dynamic' output:
              Mac Address Table
    -------------------------------------------

    Vlan    Mac Address       Type        Ports
    ----    -----------       --------    -----
       1    38fc.98c7.9c64    DYNAMIC     Gi1/0/24
       1    88a2.9e10.f172    DYNAMIC     Gi1/0/2
    Total Mac Addresses for this criterion: 10
    """
    mac_table = {}
    lines = output.strip().split("\n")

    if DEBUG:
        log.info("  [DEBUG] === MAC TABLE RAW (first 20 lines) ===")
        for line in lines[:20]:
            log.info(f"  [DEBUG] |{line}|")

    for line in lines:
        stripped = line.strip()

        # Skip headers and footers
        if not stripped or "Mac Address" in stripped or "---" in stripped or "Total" in stripped or "Unicast" in stripped:
            continue

        # Find MAC (dot format) and port name in the line
        mac_matches = re.findall(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", stripped)
        port_matches = re.findall(r"(?:Gi|Te|Fa)\d+/\d+/\d+", stripped)

        if mac_matches and port_matches:
            mac = normalize_mac(mac_matches[0])
            port_name = port_matches[0]

            # For ports with multiple MACs (like uplink Gi1/0/24),
            # keep the first one found — or overwrite (last wins)
            # Uplink ports will have many MACs, access ports usually have one
            if port_name not in mac_table:
                mac_table[port_name] = mac
                if DEBUG:
                    log.info(f"  [MAC] {port_name} → {mac}")
            else:
                if DEBUG:
                    log.info(f"  [MAC] {port_name} → {mac} (additional MAC, keeping first)")

    log.info(f"  Parsed {len(mac_table)} unique port MAC entries")
    return mac_table


def parse_arp_table(output):
    """
    C3650 'show ip arp' output:
    Protocol  Address          Age (min)  Hardware Addr   Type   Interface
    Internet  192.168.8.2             -   3890.a54b.d4c7  ARPA   Vlan1
    Internet  192.168.8.3            22   7872.5dcd.06d4  ARPA   Vlan1
    Internet  192.168.8.164           0   a6d0.f90c.868c  ARPA   Vlan1
    """
    arp_table = {}
    lines = output.strip().split("\n")

    if DEBUG:
        log.info("  [DEBUG] === ARP TABLE RAW (first 20 lines) ===")
        for line in lines[:20]:
            log.info(f"  [DEBUG] |{line}|")

    for line in lines:
        stripped = line.strip()

        if not stripped or "Protocol" in stripped or "---" in stripped or "Incomplete" in stripped:
            continue

        # Find IP and MAC anywhere in the line
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", stripped)
        mac_match = re.search(r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", stripped)

        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = normalize_mac(mac_match.group(1))

            # Skip the switch's own IP (the SVI)
            if ip == SWITCH_CONFIG["host"]:
                if DEBUG:
                    log.info(f"  [ARP] {mac} → {ip} (switch SVI, skipping)")
                continue

            arp_table[mac] = ip
            if DEBUG:
                log.info(f"  [ARP] {mac} → {ip}")

    log.info(f"  Parsed {len(arp_table)} ARP entries")
    return arp_table


def parse_ip_interface_brief(output):
    """
    C3650 'show ip interface brief' output:
    Interface              IP-Address      OK? Method Status                Protocol
    Vlan1                  192.168.8.2     YES manual up                    up
    GigabitEthernet1/0/1   unassigned      YES unset  up                    down
    GigabitEthernet1/0/2   unassigned      YES unset  up                    up
    """
    interface_ips = {}
    lines = output.strip().split("\n")

    for line in lines:
        if not line.strip() or ("Interface" in line and "IP-Address" in line):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        interface = parts[0]
        ip = parts[1]

        if ip == "unassigned" or not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
            continue

        # Shorten interface name
        short_name = interface
        short_name = short_name.replace("GigabitEthernet", "Gi")
        short_name = short_name.replace("TenGigabitEthernet", "Te")
        short_name = short_name.replace("FastEthernet", "Fa")

        interface_ips[short_name] = ip

        if DEBUG:
            log.info(f"  [L3 IP] {short_name} → {ip}")

    log.info(f"  Parsed {len(interface_ips)} routed interface IPs")
    return interface_ips


# ============================================================
# HELPERS
# ============================================================


def extract_port_number(port_name):
    """
    C3650 port naming:
      Gi1/0/1  - Gi1/0/24  → Ports 1-24
      Gi1/1/1  - Gi1/1/4   → Ports 25-28

    Extract based on slot and port:
      Gi1/0/X → X
      Gi1/1/X → 24 + X
    """
    match = re.match(r"(?:Gi|Te|Fa)(\d+)/(\d+)/(\d+)", port_name)
    if match:
        slot = int(match.group(2))    # 0 or 1
        port = int(match.group(3))    # port number
        if slot == 0:
            return port               # 1-24
        elif slot == 1:
            return 24 + port          # 25-28
    return 0


def port_number_to_interface(port_number):
    """
    Convert port number back to C3650 interface name:
      1-24  → GigabitEthernet1/0/1 - GigabitEthernet1/0/24
      25-28 → GigabitEthernet1/1/1 - GigabitEthernet1/1/4
    """
    if port_number <= 24:
        return f"GigabitEthernet1/0/{port_number}"
    else:
        return f"GigabitEthernet1/1/{port_number - 24}"


def map_port_status(cisco_status):
    return {
        "connected": "active",
        "notconnect": "disabled",
        "disabled": "disabled",
        "err-disabled": "isolated",
        "monitoring": "warning",
    }.get(cisco_status, "disabled")


def parse_vlan(vlan_raw):
    if vlan_raw in ["trunk", "routed"]:
        return 0
    try:
        return int(vlan_raw)
    except BaseException:
        return 1


def parse_speed(speed_raw, port_name):
    s = speed_raw.lower().replace("a-", "")
    if "10000" in s or "10g" in s:
        return "10G"
    elif "1000" in s or "1g" in s:
        return "1G"
    elif "100" in s:
        return "100M"
    elif "10" in s:
        return "10M"
    return "1G"


def normalize_mac(mac_string):
    """38fc.98c7.9c64 → 38:FC:98:C7:9C:64"""
    clean = mac_string.replace(".", "").replace(":", "").replace("-", "").upper()
    if len(clean) != 12:
        return mac_string.upper()
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def octets_to_mb(octets):
    return round(octets / (1024 * 1024), 1)


# ============================================================
# SWITCH COMMANDS — VLAN Isolation
# ============================================================


def ensure_quarantine_vlan(conn):
    try:
        output = cmd(conn, "show vlan brief")
        if str(QUARANTINE_VLAN) in output:
            return True
        commands = [
            f"vlan {QUARANTINE_VLAN}",
            f"name {QUARANTINE_VLAN_NAME}",
            "exit",
        ]
        conn.send_config_set(commands)
        log.info(f"Created VLAN {QUARANTINE_VLAN}")
        return True
    except Exception as e:
        log.error(f"Failed to create quarantine VLAN: {e}")
        return False


def get_port_vlan_on_switch(conn, interface):
    try:
        output = cmd(conn, f"show interfaces {interface} switchport")
        for line in output.split("\n"):
            if "Access Mode VLAN" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    vlan_str = parts[1].strip().split()[0]
                    return int(vlan_str)
        return 1
    except Exception as e:
        log.error(f"Failed to get VLAN for {interface}: {e}")
        return 1


def isolate_port_on_switch(conn, port_number):
    interface = port_number_to_interface(port_number)
    try:
        ensure_quarantine_vlan(conn)
        current_vlan = get_port_vlan_on_switch(conn, interface)
        log.info(f"  [ISOLATE] {interface} current VLAN: {current_vlan}")

        if current_vlan == QUARANTINE_VLAN:
            log.info(f"  Port {port_number} already in quarantine")
            return True

        commands = [
            f"interface {interface}",
            "switchport mode access",
            f"switchport access vlan {QUARANTINE_VLAN}",
            "no shutdown",
            "exit",
        ]
        result = conn.send_config_set(commands)
        log.info(f"  [ISOLATE] Config result: {result}")

        new_vlan = get_port_vlan_on_switch(conn, interface)
        log.info(f"  [ISOLATE] {interface} new VLAN: {new_vlan}")

        if new_vlan == QUARANTINE_VLAN:
            log.info(f"✓ ISOLATED port {port_number} ({interface}): VLAN {current_vlan} → {QUARANTINE_VLAN}")
            return True
        else:
            log.error(f"✗ Isolation FAILED for port {port_number}. Expected {QUARANTINE_VLAN}, got {new_vlan}")
            return False
    except Exception as e:
        log.error(f"Error isolating port {port_number}: {e}")
        return False


def lift_isolation_on_switch(conn, port_number, original_vlan):
    interface = port_number_to_interface(port_number)
    try:
        log.info(f"  [LIFT] Restoring {interface} to VLAN {original_vlan}")

        commands = [
            f"interface {interface}",
            "switchport mode access",
            f"switchport access vlan {original_vlan}",
            "no shutdown",
            "exit",
        ]
        result = conn.send_config_set(commands)
        log.info(f"  [LIFT] Config result: {result}")

        new_vlan = get_port_vlan_on_switch(conn, interface)
        log.info(f"  [LIFT] {interface} new VLAN: {new_vlan}")

        if new_vlan == original_vlan:
            log.info(f"✓ RESTORED port {port_number} ({interface}): VLAN {QUARANTINE_VLAN} → {original_vlan}")
            return True
        else:
            log.error(f"✗ Restore FAILED for port {port_number}. Expected {original_vlan}, got {new_vlan}")
            return False
    except Exception as e:
        log.error(f"Error restoring port {port_number}: {e}")
        return False


# ============================================================
# API CALLS
# ============================================================


def get_existing_ports():
    try:
        r = requests.get(f"{API_CONFIG['base_url']}/ports", timeout=API_CONFIG["timeout"])
        if r.status_code == 200:
            return {p["port_number"]: p for p in r.json()}
        return {}
    except Exception as e:
        log.error(f"API fetch failed: {e}")
        return {}


def create_port_api(data):
    try:
        r = requests.post(f"{API_CONFIG['base_url']}/ports", json=data, timeout=API_CONFIG["timeout"])
        if r.status_code == 200:
            log.info(f"  Created port {data['port_number']}")
            return True
        log.warning(f"  Create port {data['port_number']} failed: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        log.error(f"  Create port {data['port_number']} error: {e}")
        return False


def update_port_api(port_number, data):
    try:
        r = requests.put(f"{API_CONFIG['base_url']}/ports/{port_number}", json=data, timeout=API_CONFIG["timeout"])
        return r.status_code == 200
    except Exception as e:
        log.error(f"  Update port {port_number} error: {e}")
        return False


# ============================================================
# ISOLATION DETECTION
# ============================================================


def check_and_execute_isolations(conn, db_ports, switch_ports):
    """
    Compare DB status with actual switch VLAN.
    - DB=isolated + switch not in VLAN 999 → isolate on switch, update DB vlan to 999
    - DB=active + switch still in VLAN 999 → restore original VLAN, clear original_vlan
    """
    actions = 0

    # Build port_number → switch VLAN lookup
    switch_vlan_map = {}
    for pname, pdata in switch_ports.items():
        switch_vlan_map[pdata["port_number"]] = {
            "vlan": pdata["vlan"],
            "port_name": pname,
        }

    if DEBUG:
        iso_ports = {k: v.get("status") for k, v in db_ports.items() if v.get("status") == "isolated"}
        if iso_ports:
            log.info(f"  [ISO CHECK] Isolated ports in DB: {iso_ports}")
            log.info("  [ISO CHECK] Switch VLAN map: " + str({k: v['vlan'] for k, v in switch_vlan_map.items()}))

    for port_num, db_port in db_ports.items():
        db_status = db_port.get("status")
        original_vlan = db_port.get("original_vlan")

        if db_status not in ["isolated", "active"]:
            continue

        switch_info = switch_vlan_map.get(port_num)
        if switch_info is None:
            if db_status == "isolated":
                log.warning(f"  [ISO CHECK] Port {port_num} isolated in DB but NOT FOUND in switch!")
                log.warning(f"  [ISO CHECK] Available switch ports: {sorted(switch_vlan_map.keys())}")
            continue

        switch_vlan = switch_info["vlan"]
        port_name = switch_info["port_name"]

        if DEBUG:
            log.info(f"  [ISO CHECK] Port {port_num} ({port_name}): DB={db_status}, Switch VLAN={switch_vlan}, Original={original_vlan}")

        # Case 1: DB says ISOLATED but switch NOT in quarantine → isolate
        if db_status == "isolated" and switch_vlan != QUARANTINE_VLAN:
            log.info(f"⚡ ISOLATING Port {port_num} ({port_name}): VLAN {switch_vlan} → {QUARANTINE_VLAN}")
            if isolate_port_on_switch(conn, port_num):
                update_port_api(port_num, {"vlan": QUARANTINE_VLAN})
                actions += 1
            else:
                log.error(f"  ISOLATION FAILED for port {port_num}!")

        # Case 2: DB says ACTIVE but switch still in quarantine → restore
        elif db_status == "active" and switch_vlan == QUARANTINE_VLAN:
            restore_vlan = original_vlan or 1
            log.info(f"⚡ RESTORING Port {port_num} ({port_name}): VLAN {QUARANTINE_VLAN} → {restore_vlan}")
            if lift_isolation_on_switch(conn, port_num, restore_vlan):
                update_port_api(port_num, {"vlan": restore_vlan, "original_vlan": None})
                actions += 1
            else:
                log.error(f"  RESTORE FAILED for port {port_num}!")

    return actions


# ============================================================
# MAIN POLL CYCLE
# ============================================================


def poll_switch(conn):
    log.info("Polling switch...")

    # Run all show commands
    status_out = cmd(conn, "show interfaces status")
    counters_out = cmd(conn, "show interfaces counters")
    errors_out = cmd(conn, "show interfaces counters errors")
    mac_out = cmd(conn, "show mac address-table dynamic")

    # Ping sweep the subnet to populate ARP table
    # This forces the switch to ARP for all active devices
    log.info("  Running ARP refresh ping sweep...")
    try:
        conn.send_command("ping 192.168.8.255 repeat 1 timeout 1", read_timeout=10)
    except BaseException:
        pass  # Broadcast ping may fail but still populates ARP

    arp_out = cmd(conn, "show ip arp")
    ip_brief_out = cmd(conn, "show ip interface brief")

    # Parse all outputs
    ports = parse_interfaces_status(status_out)
    counters = parse_interfaces_counters(counters_out)
    errors = parse_interfaces_errors(errors_out)
    mac_table = parse_mac_address_table(mac_out)
    arp_table = parse_arp_table(arp_out)
    interface_ips = parse_ip_interface_brief(ip_brief_out)

    if not ports:
        log.warning("No ports parsed.")
        if DEBUG:
            log.info("  [DEBUG] Raw 'show interfaces status' (first 10 lines):")
            for line in status_out.strip().split("\n")[:10]:
                log.info(f"  [DEBUG] |{line}|")
        return 0

    log.info(f"Parsed {len(ports)} ports, {len(mac_table)} MACs, {len(arp_table)} ARPs, {len(interface_ips)} L3 IPs")

    # Get DB state
    db_ports = get_existing_ports()

    # Execute pending isolations/lifts FIRST
    iso_actions = check_and_execute_isolations(conn, db_ports, ports)
    if iso_actions > 0:
        log.info(f"Executed {iso_actions} actions. Re-reading switch...")
        status_out = cmd(conn, "show interfaces status")
        ports = parse_interfaces_status(status_out)

    # Push data to API
    created = 0
    updated = 0

    for port_name, port_info in ports.items():
        port_num = port_info["port_number"]
        if port_num == 0:
            continue

        # Look up MAC and IP
        mac = mac_table.get(port_name)
        ip = arp_table.get(mac) if mac else None

        # For routed interfaces (VLAN=0), use the interface's own IP
        if not ip and port_info["vlan"] == 0:
            ip = interface_ips.get(port_name)
            if DEBUG and ip:
                log.info(f"  [ROUTED] {port_name}: L3 IP={ip}")

        if DEBUG and mac:
            log.info(f"  [LOOKUP] {port_name}: MAC={mac}, IP={ip}")

        port_counters = counters.get(port_name, {"in_octets": 0, "out_octets": 0})
        port_errors = errors.get(port_name, {"errors": 0, "drops": 0})

        port_data = {
            "port_number": port_num,
            "status": port_info["status"],
            "device_ip": ip or "",
            "device_mac": mac or "",
            "device_name": port_info["device_name"],
            "vlan": port_info["vlan"],
            "speed": port_info["speed"],
            "bytes_sent": octets_to_mb(port_counters["out_octets"]),
            "bytes_received": octets_to_mb(port_counters["in_octets"]),
            "errors": port_errors["errors"],
            "drops": port_errors["drops"],
            "last_activity": datetime.now(timezone.utc).isoformat(),
        }

        if port_num in db_ports:
            existing = db_ports[port_num]

            # Don't overwrite isolated status from DB
            if existing.get("status") == "isolated":
                update = {
                    "bytes_sent": port_data["bytes_sent"],
                    "bytes_received": port_data["bytes_received"],
                    "errors": port_errors["errors"],
                    "drops": port_errors["drops"],
                    "last_activity": port_data["last_activity"],
                }
            else:
                update = {
                    "status": port_data["status"],
                    "device_name": port_data["device_name"],
                    "vlan": port_data["vlan"],
                    "speed": port_data["speed"],
                    "bytes_sent": port_data["bytes_sent"],
                    "bytes_received": port_data["bytes_received"],
                    "errors": port_errors["errors"],
                    "drops": port_errors["drops"],
                    "last_activity": port_data["last_activity"],
                }

                # Only update IP and MAC if we have values
                # Don't overwrite existing data with empty strings
                if port_data["device_ip"]:
                    update["device_ip"] = port_data["device_ip"]
                if port_data["device_mac"]:
                    update["device_mac"] = port_data["device_mac"]

            if update_port_api(port_num, update):
                updated += 1
        else:
            if create_port_api(port_data):
                created += 1

    log.info(f"Poll complete: {created} created, {updated} updated, {iso_actions} isolations")
    return created + updated


# ============================================================
# ENTRY POINT
# ============================================================


def main():
    log.info("=" * 55)
    log.info("  IoT SOC — C3650 Switch Poller")
    log.info(f"  Switch: {SWITCH_CONFIG['host']}")
    log.info(f"  API:    {API_CONFIG['base_url']}")
    log.info(f"  Poll:   {POLL_INTERVAL}s")
    log.info(f"  VLAN:   {QUARANTINE_VLAN}")
    log.info(f"  Debug:  {DEBUG}")
    log.info("=" * 55)

    conn = None
    fails = 0

    while True:
        try:
            if conn is None or not conn.is_alive():
                if conn:
                    try:
                        conn.disconnect()
                    except BaseException:
                        pass
                conn = connect_to_switch()
                if not conn:
                    fails += 1
                    if fails >= 5:
                        log.error("5 consecutive failures. Waiting 60s...")
                        time.sleep(60)
                        fails = 0
                    else:
                        time.sleep(POLL_INTERVAL)
                    continue

            result = poll_switch(conn)
            fails = 0 if result > 0 else fails + 1

        except KeyboardInterrupt:
            log.info("\nStopping...")
            if conn:
                conn.disconnect()
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            fails += 1
            conn = None

        time.sleep(POLL_INTERVAL)

    log.info("Poller stopped.")


if __name__ == "__main__":
    main()
