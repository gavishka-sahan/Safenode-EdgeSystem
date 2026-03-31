from typing import Dict, List


FEATURE_NAMES: Dict[int, str] = {
    # Flow Metrics (0-2)
    0: "flow_duration",
    1: "rate",                    # pkts_per_sec
    2: "bytes_per_sec",

    # TCP Flag Counts (3-9)
    3: "syn_count",
    4: "ack_count",
    5: "rst_count",
    6: "urg_count",
    7: "psh_flag_count",
    8: "fin_flag_count",
    9: "tcp_flags",               # avg of raw TCP flag values

    # Protocol Binary Flags (10-23)
    10: "TCP",
    11: "UDP",
    12: "ICMP",
    13: "ARP",
    14: "DNS",
    15: "HTTP",
    16: "HTTPS",
    17: "Telnet",
    18: "SMTP",
    19: "SSH",
    20: "IRC",
    21: "DHCP",
    22: "IPv4",
    23: "LLC",

    # IP Protocol Number (24)
    24: "proto",                  # ip.proto

    # Packet Size Statistics (25-26)
    25: "pkt_size_avg",           # avg_packet_size
    26: "packet_size_variance",

    # Packet and Byte Counts (27-32)
    27: "packet_count",
    28: "byte_count",
    29: "fwd_packet_count",
    30: "bwd_packet_count",
    31: "fwd_byte_count",
    32: "bwd_byte_count",

    # Directional Packet Length Means (33-34)
    33: "fwd_packet_len_mean",
    34: "bwd_packet_len_mean",

    # Aggregate Size Metrics (35-38)
    35: "Tot_size",
    36: "Tot_sum",
    37: "AVG",                    # same as pkt_size_avg
    38: "Std",                    # std dev of packet sizes

    # Inter-Arrival Time Metrics (39-43)
    39: "iat_mean",               # avg_iat
    40: "iat_std",                # iat_variance
    41: "min_iat",
    42: "max_iat",
    43: "IAT",                    # total inter-arrival time

    # Frame and TCP Time Deltas (44-45)
    44: "frame.time_delta",
    45: "tcp.time_delta",

    # Frame and TCP Metrics (46-49)
    46: "tcp.len",
    47: "frame.len",
    48: "frame.cap_len",
    49: "tcp.window_size_value",

    # MQTT Features (50-55)
    50: "mqtt.msgtype",
    51: "mqtt.qos",
    52: "mqtt.dupflag",
    53: "mqtt.retain",
    54: "mqtt.len",
    55: "mqtt.topic_len",

    # IP Metadata (56-58)
    56: "ttl_value",
    57: "ip_header_len",
    58: "Init_Win_bytes_Fwd",

    # Source and Destination IPs (59-60)
    59: "source_IP",
    60: "Destination_IP",
}

# Total number of features in the system
TOTAL_FEATURES = 61


def get_feature_name(index: int) -> str:
    """Get human-readable name for a feature index (for logging)"""
    return FEATURE_NAMES.get(index, f"unknown_feature_{index}")


def convert_named_to_indexed(named_features: dict) -> dict:
    name_to_index = {name: idx for idx, name in FEATURE_NAMES.items()}

    indexed_features = {}
    skipped_features = []

    for feature_name, value in named_features.items():
        if feature_name in ['timestamp', 'device_id', 'flow_id', 'feature_id',
                            'src_ip', 'dst_ip', 'src_mac', 'dst_mac',
                            'src_port', 'dst_port', 'protocol']:
            continue

        if feature_name in name_to_index:
            index = name_to_index[feature_name]
            indexed_features[index] = value
        else:
            skipped_features.append(feature_name)

    if skipped_features:
        print(f"Warning: Skipped {len(skipped_features)} unknown features: {skipped_features[:5]}")

    return indexed_features


def validate_indices(indices: List[int]) -> bool:
    """Validate that all indices are within valid range (0-60)"""
    return all(0 <= idx <= 60 for idx in indices)


def get_feature_indices_for_model(model_name: str) -> List[int]:
    MODEL_FEATURES = {
        # MIRAI BOTNET
        'mirai': [
            0, 0, 1, 3, 6, 5, 15, 16, 14, 17, 18, 19, 20, 10, 11, 21, 13, 12,
        ],

        # DOS ATTACK
        'dos': [
            1, 2, 25, 24, 9, 3, 4, 5, 39, 40,
        ],

        # SPOOFING
        'spoof': [
            # 13,14,23,0,1,43,35,36,37,38,4,3,10,11,12,22,
            56, 24, 49, 58, 57, 3, 5, 4, 13, 14, 40, 8, 7, 10, 11,
        ],

        # REPLAY ATTACK
        'replay': [
            # 44,45,46,47,48,49,9,50,51,52,53,54,55,24,
            52, 58, 40, 39, 26, 49, 5, 3, 56, 54,
        ],
    }

    return MODEL_FEATURES.get(model_name.lower(), [])


def get_model_info(model_name: str) -> Dict:
    MODEL_INFO = {
        'mirai': {
            'full_name': 'Mirai Botnet Detection',
            'attack_types': ['Mirai DDoS', 'Port Scanning', 'Telnet Brute Force'],
            'feature_count': 0,
            'model_file': 'mirai_model.onnx',
            'requires_scaler': False,
            'accuracy': 0.9999,
            'inference_time_ms': 1.71,
            'dataset': 'bornpresident/mirai_botnet (Hugging Face)',
            'classes': {
                0: 'BenignTraffic',
                1: 'Mirai-greeth_flood',
                2: 'Mirai-greip_flood',
                3: 'Mirai-udpplain'
            },
            'primary_indicators': [
                'UDP protocol (63.3% importance for DDoS floods)',
                'Telnet port (23) - primary infection vector',
                'High packet rate with small packets',
                'TCP flag patterns (SYN scanning)',
            ]
        },
        'replay': {
            'full_name': 'Replay Attack Detection',
            'attack_types': ['Replay Attack', 'MQTT Replay'],
            'feature_count': 0,
            'model_file': 'replay_model.onnx',
            'model_format': 'XGBoost JSON',
            'requires_scaler': True,
            'dataset': 'Teammate dataset'
        },
        'dos': {
            'full_name': 'DoS Attack Detection',
            'attack_types': ['DDoS', 'SYN Flood', 'UDP Flood'],
            'feature_count': 0,
            'model_file': 'dos_model.onnx',
            'requires_scaler': True,
            'dataset': 'Teammate dataset',
        },
        'sniffing': {
            'full_name': 'Sniffing/Spoofing Detection',
            'attack_types': ['ARP Spoofing', 'DNS Spoofing', 'MAC Spoofing'],
            'feature_count': 0,
            'model_file': 'spoof_model.onnx',
            'requires_scaler': False,
            'dataset': 'CIC IoT Dataset 2023',
        }
    }

    return MODEL_INFO.get(model_name.lower(), {})


if __name__ == "__main__":
    print("=" * 80)
    print(f"FEATURE INDEX MAPPING SYSTEM - v6.0 ({TOTAL_FEATURES} Features)")
    print("=" * 80)

    print(f"\nTotal Features: {TOTAL_FEATURES}")
    print("\nFeature Index -> Name Mapping:")
    print("-" * 80)

    for idx in range(TOTAL_FEATURES):
        print(f"  [{idx:2d}] {get_feature_name(idx)}")

    print("\n" + "=" * 80)
    print("MODEL FEATURE REQUIREMENTS")
    print("=" * 80)

    for model in ['mirai', 'replay', 'dos', 'sniffing']:
        indices = get_feature_indices_for_model(model)
        info = get_model_info(model)

        print(f"\n{model.upper()} Model - {info.get('full_name', 'Unknown')}:")
        print(f"  Model file: {info.get('model_file', 'unknown')}")
        print(f"  Requires {len(indices)} features")
        print(f"  Feature indices: {indices}")

        if validate_indices(indices):
            print(f"  All indices valid (0-{TOTAL_FEATURES - 1})")
        else:
            print("  ERROR: Invalid indices detected!")

        if len(indices) > 0:
            print("  Features used:")
            for idx in indices[:10]:
                print(f"    [{idx:2d}] {get_feature_name(idx)}")
            if len(indices) > 10:
                print(f"    ... and {len(indices) - 10} more")

    print("\n" + "=" * 80)
    print("VALIDATION COMPLETE")
    print("=" * 80)

    all_features_used = set()
    for model in ['mirai', 'replay', 'dos', 'sniffing']:
        indices = get_feature_indices_for_model(model)
        all_features_used.update(indices)

    print(f"\nTotal unique features used across all models: {len(all_features_used)}")
    print(f"Feature coverage: {len(all_features_used)}/{TOTAL_FEATURES} "
          f"({len(all_features_used) / TOTAL_FEATURES * 100:.1f}%)")
