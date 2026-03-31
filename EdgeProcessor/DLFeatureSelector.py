"""
Cloud Feature Selector - 27 Features for Cloud ML Validation
=============================================================

This module maps the 27 features required by the cloud ML model
from the 61-feature system used by the Edge ML module.

The Edge ML receives all 61 features but only needs to forward
27 specific features to the cloud for deep learning validation.

Author: Gavishka's Team
Date: February 2026
Version: 1.0
"""

from typing import Dict
from FeatureIndexMap import FEATURE_NAMES


# ============================================================================
# CLOUD FEATURE MAPPING (27 features)
# ============================================================================

# Map cloud feature names to their indices in the 61-feature system
CLOUD_FEATURE_INDICES: Dict[str, int] = {
    # Basic IP/TCP metadata
    'ttl_value': 56,
    'ip_header_len': 57,
    'Init_Win_bytes_Fwd': 58,

    # Packet and byte counts
    'packet_count': 27,
    'byte_count': 28,
    'packets_per_sec': 1,        # rate
    'bytes_per_sec': 2,

    # Directional counts
    'fwd_packet_count': 29,
    'bwd_packet_count': 30,
    'fwd_byte_count': 31,
    'bwd_byte_count': 32,

    # Packet size statistics
    'avg_packet_size': 25,       # pkt_size_avg
    'packet_size_variance': 26,
    'bwd_packet_len_mean': 34,
    'fwd_packet_len_mean': 33,

    # Flow timing
    'flow_duration': 0,

    # Inter-arrival time statistics
    'avg_iat': 39,               # iat_mean
    'min_iat': 41,
    'max_iat': 42,
    'iat_variance': 40,          # iat_std
    'flow_iat_std': 40,          # same as iat_std

    # TCP flags
    'syn_flag_count': 3,         # syn_count
    'ack_flag_count': 4,         # ack_count
    'rst_flag_count': 5,         # rst_count
    'psh_flag_count': 7,
    'fin_flag_count': 8,
    'urg_flag_count': 6,         # urg_count
}

# Create reverse mapping for validation
CLOUD_INDICES = list(set(CLOUD_FEATURE_INDICES.values()))
CLOUD_INDICES.sort()

# Total cloud features
TOTAL_CLOUD_FEATURES = 27


def select_cloud_features(indexed_features: Dict[int, float]) -> Dict[str, float]:
    """
    Extract the 27 cloud features from the 61-feature metadata.

    Args:
        indexed_features: Dictionary with integer keys (0-60) from Edge ML

    Returns:
        Dictionary with cloud feature names as keys and values

    Example:
        >>> features = {0: 5.5, 1: 10.2, 27: 150, ...}  # 61 features
        >>> cloud_features = select_cloud_features(features)
        >>> # Returns: {'flow_duration': 5.5, 'packets_per_sec': 10.2, ...}  # 27 features
    """
    cloud_features = {}

    for feature_name, index in CLOUD_FEATURE_INDICES.items():
        # Get feature value from indexed features
        value = indexed_features.get(index, 0.0)
        cloud_features[feature_name] = value

    return cloud_features


def select_cloud_features_indexed(indexed_features: Dict[int, float]) -> Dict[int, float]:
    """
    Extract cloud features but keep them indexed (for compatibility).

    Args:
        indexed_features: Dictionary with integer keys (0-60) from Edge ML

    Returns:
        Dictionary with only the 27 cloud feature indices and values

    Example:
        >>> features = {0: 5.5, 1: 10.2, 27: 150, ...}  # 61 features
        >>> cloud_indexed = select_cloud_features_indexed(features)
        >>> # Returns: {0: 5.5, 1: 10.2, 27: 150, ...}  # Only 27 indices
    """
    cloud_indexed = {}

    for index in CLOUD_INDICES:
        if index in indexed_features:
            cloud_indexed[index] = indexed_features[index]
        else:
            cloud_indexed[index] = 0.0

    return cloud_indexed


def validate_cloud_features(cloud_features: Dict[str, float]) -> bool:
    """
    Validate that all 27 cloud features are present.

    Args:
        cloud_features: Dictionary with cloud feature names as keys

    Returns:
        True if all 27 features present, False otherwise
    """
    if len(cloud_features) != TOTAL_CLOUD_FEATURES:
        print(f"❌ Expected {TOTAL_CLOUD_FEATURES} features, got {len(cloud_features)}")
        return False

    missing = set(CLOUD_FEATURE_INDICES.keys()) - set(cloud_features.keys())
    if missing:
        print(f"❌ Missing features: {missing}")
        return False

    return True


def get_cloud_feature_info() -> Dict:
    """Get information about cloud features"""
    return {
        'total_features': TOTAL_CLOUD_FEATURES,
        'feature_names': list(CLOUD_FEATURE_INDICES.keys()),
        'feature_indices': CLOUD_INDICES,
        'index_mapping': CLOUD_FEATURE_INDICES,
        'categories': {
            'IP/TCP metadata': ['ttl_value', 'ip_header_len', 'Init_Win_bytes_Fwd'],
            'Packet/Byte counts': ['packet_count', 'byte_count', 'packets_per_sec', 'bytes_per_sec'],
            'Directional': ['fwd_packet_count', 'bwd_packet_count', 'fwd_byte_count', 'bwd_byte_count'],
            'Packet sizes': ['avg_packet_size', 'packet_size_variance', 'bwd_packet_len_mean', 'fwd_packet_len_mean'],
            'Flow timing': ['flow_duration'],
            'Inter-arrival times': ['avg_iat', 'min_iat', 'max_iat', 'iat_variance', 'flow_iat_std'],
            'TCP flags': ['syn_flag_count', 'ack_flag_count', 'rst_flag_count', 'psh_flag_count', 'fin_flag_count', 'urg_flag_count']
        }
    }


# ============================================================================
# VALIDATION AND TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("CLOUD FEATURE SELECTOR - 27 Features for Cloud ML")
    print("=" * 80)

    info = get_cloud_feature_info()

    print(f"\nTotal Cloud Features: {info['total_features']}")
    print("\nFeature Indices Used (from 61-feature system):")
    print(f"  {CLOUD_INDICES}")

    print("\n" + "=" * 80)
    print("CLOUD FEATURE MAPPING")
    print("=" * 80)

    for category, features in info['categories'].items():
        print(f"\n{category}:")
        for feature in features:
            index = CLOUD_FEATURE_INDICES[feature]
            original_name = FEATURE_NAMES.get(index, 'unknown')
            print(f"  {feature:25s} <- Index {index:2d} ({original_name})")

    print("\n" + "=" * 80)
    print("TESTING FEATURE SELECTION")
    print("=" * 80)

    # Create sample 61-feature input
    sample_features = {i: float(i * 10) for i in range(61)}

    # Test named output
    cloud_named = select_cloud_features(sample_features)
    print(f"\nNamed Features Output: {len(cloud_named)} features")
    print(f"Validation: {'✓ PASS' if validate_cloud_features(cloud_named) else '✗ FAIL'}")

    # Test indexed output
    cloud_indexed = select_cloud_features_indexed(sample_features)
    print(f"\nIndexed Features Output: {len(cloud_indexed)} features")
    print(f"Indices: {sorted(cloud_indexed.keys())}")

    # Show first few features
    print("\nSample Output (first 10 features):")
    for i, (name, value) in enumerate(list(cloud_named.items())[:10]):
        index = CLOUD_FEATURE_INDICES[name]
        print(f"  {name:25s} = {value:6.1f} (index {index})")

    print("\n" + "=" * 80)
    print("✓ VALIDATION COMPLETE")
    print("=" * 80)
