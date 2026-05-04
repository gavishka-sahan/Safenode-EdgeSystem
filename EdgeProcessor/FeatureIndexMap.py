from typing import Dict, List


FEATURE_NAMES: Dict[int, str] = {
    0: "flow_duration",
    1: "rate",                    # pkts_per_sec
    2: "bytes_per_sec",
    3: "syn_count",
    4: "ack_count",
    5: "rst_count",
    6: "urg_count",
    7: "psh_flag_count",
    8: "fin_flag_count",
    9: "tcp_flags",               # avg of raw TCP flag values
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
    24: "proto",                  # ip.proto
    25: "pkt_size_avg",           # avg_packet_size
    26: "packet_size_variance",
    27: "packet_count",
    28: "byte_count",
    29: "fwd_packet_count",
    30: "bwd_packet_count",
    31: "fwd_byte_count",
    32: "bwd_byte_count",
    33: "fwd_packet_len_mean",
    34: "bwd_packet_len_mean",
    35: "Tot_size",
    36: "Tot_sum",
    37: "AVG",                    # same as pkt_size_avg
    38: "Std",                    # std dev of packet sizes
    39: "iat_mean",               # avg_iat
    40: "iat_std",                # iat_variance
    41: "min_iat",
    42: "max_iat",
    43: "IAT",                    # total inter-arrival time (sum)
    44: "frame.time_delta",
    45: "tcp.time_delta",
    46: "tcp.len",
    47: "frame.len",
    48: "frame.cap_len",
    49: "tcp.window_size_value",
    50: "mqtt.msgtype",
    51: "mqtt.qos",
    52: "mqtt.dupflag",
    53: "mqtt.retain",
    54: "mqtt.len",
    55: "mqtt.topic_len",
    56: "ttl_value",
    57: "ip_header_len",
    58: "Init_Win_bytes_Fwd",
    59: "source_IP",
    60: "Destination_IP",
    61: "gre_inner_protocol",     # avg inner protocol number inside GRE packets
    62: "fwd_bwd_ratio",          # fwd_packet_count / bwd_packet_count
    63: "frame_time_delta_bin",   # 1 if any frame_time_delta > threshold, else 0
    64: "ip_len",                 # avg ip.len (IP total length field)
    65: "payload_size",           # avg TCP/UDP application payload bytes
    66: "Max",                    # max frame size in bytes
    67: "Min",                    # min frame size in bytes
    68: "psh_flag_number",        # ratio of PSH flagged packets
    69: "syn_flag_number",        # ratio of SYN flagged packets
    70: "ack_flag_number",        # ratio of ACK flagged packets
}

# Total number of features in the system
TOTAL_FEATURES = 71


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
    """Validate that all indices are within valid range (0-70)"""
    return all(0 <= idx <= 70 for idx in indices)


def get_feature_indices_for_model(model_name: str) -> List[int]:
    MODEL_FEATURES = {
        'replay': [63, 47, 64, 56, 57, 49, 3, 5, 8, 4, 7, 65, 52],

        'dos': [43, 1, 66, 68, 10, 38, 26, 11, 37, 35, 69, 70, 3, 15, 5, 12, 8, 67],

        'mirai': [0, 25, 1, 40, 3, 8, 14, 10, 11, 5],

        'spoof': [56, 3, 4, 5, 39, 40, 1, 0, 49, 25, 13, 14, 24, 29, 30],

    }

    return MODEL_FEATURES.get(model_name.lower(), [])


def get_model_info(model_name: str) -> Dict:
    MODEL_INFO = {
        'mirai': {
            'full_name': 'Mirai Botnet Detection',

            'attack_types': ['Mirai-greeth_flood', 'Mirai-greip_flood', 'Mirai-udpplain'],
            'feature_count': 10,
            'model_file': 'mirai_model.onnx',
            'requires_scaler': False,
            'dataset': 'CICIoT2023',
            'classes': {
                0: 'BenignTraffic',
                1: 'Mirai-greeth_flood',
                2: 'Mirai-greip_flood',
                3: 'Mirai-udpplain'
            },
        },
        'replay': {
            'full_name': 'Replay Attack Detection',
            'attack_types': ['Replay Attack', 'MQTT Replay'],
            'feature_count': 13,
            'model_file': 'replay_model.onnx',
            'requires_scaler': True,
            'dataset': 'CICIOT2023',
            'classes': {
                0: 'BenignTraffic',
                1: 'Replay'
            },
        },
        'dos': {
            'full_name': 'DoS Attack Detection',
            'attack_types': ['SYN Flood', 'UDP Flood'],
            'feature_count': 18,
            'model_file': 'dos_model.onnx',
            'requires_scaler': True,
            'dataset': 'CICIOT2023',
            'classes': {
                0: 'BenignTraffic',
                1: 'DoS'
            },
        },
        'spoof': {
            'full_name': 'Sniffing/Spoofing Detection',
            'attack_types': ['ARP Spoofing', 'DNS Spoofing', 'MAC Spoofing'],
            'feature_count': 15,
            'model_file': 'spoof_model.onnx',
            'requires_scaler': False,
            'dataset': 'CICIoT2023',
            'classes': {
                0: 'BenignTraffic',
                1: 'Spoofing'
            },
        },
    }

    return MODEL_INFO.get(model_name.lower(), {})


if __name__ == "__main__":
    print("=" * 80)
    print(f"FEATURE INDEX MAPPING SYSTEM - v8.0 ({TOTAL_FEATURES} Features)")
    print("=" * 80)

    print(f"\nTotal Features: {TOTAL_FEATURES}")
    print("\nFeature Index -> Name Mapping:")
    print("-" * 80)

    for idx in range(TOTAL_FEATURES):
        print(f"  [{idx:2d}] {get_feature_name(idx)}")

    print("\n" + "=" * 80)
    print("MODEL FEATURE REQUIREMENTS")
    print("=" * 80)

    for model in ['mirai', 'replay', 'dos', 'spoof']:
        indices = get_feature_indices_for_model(model)
        info = get_model_info(model)

        print(f"\n{model.upper()} Model - {info.get('full_name', 'Unknown')}:")
        print(f"  Model file:      {info.get('model_file', 'unknown')}")
        print(f"  Feature count:   {len(indices)}")
        print(f"  Feature indices: {indices}")

        if validate_indices(indices):
            print(f"  Validation: ALL INDICES VALID (0-{TOTAL_FEATURES - 1})")
        else:
            print("  Validation: ERROR — invalid indices detected!")

        print("  Features used:")
        for idx in indices:
            print(f"    [{idx:2d}] {get_feature_name(idx)}")

    print("\n" + "=" * 80)
    print("COVERAGE SUMMARY")
    print("=" * 80)

    all_features_used = set()
    for model in ['mirai', 'replay', 'dos', 'spoof']:
        all_features_used.update(get_feature_indices_for_model(model))

    print(f"\nTotal unique features used across all models: {len(all_features_used)}")
    print(f"Feature coverage: {len(all_features_used)}/{TOTAL_FEATURES} "
          f"({len(all_features_used) / TOTAL_FEATURES * 100:.1f}%)")
    print(f"Unused indices: {sorted(set(range(TOTAL_FEATURES)) - all_features_used)}")
