from models_loader import scaler

"""
Explainability helpers.
Provides feature explanations, metadata, and baseline/deviation calculations.
"""
FEATURE_EXPLANATIONS = {
    'Flow Duration': {
        'description': 'Duration of the network flow',
        'high_impact': 'Very short duration indicates automated attack tools',
        'low_impact': 'Long duration suggests normal user activity'
    },
    'Total Fwd Packets': {
        'description': 'Number of packets sent from source to destination',
        'high_impact': 'Very high packet count indicates flooding attack',
        'low_impact': 'Normal packet count for regular traffic'
    },
    'Total Backward Packets': {
        'description': 'Number of packets sent from destination to source',
        'high_impact': 'Asymmetric traffic pattern may indicate attack',
        'low_impact': 'Balanced response indicates normal communication'
    },
    'Flow Bytes/s': {
        'description': 'Data transfer rate in bytes per second',
        'high_impact': 'Extremely high rate indicates DDoS or data exfiltration',
        'low_impact': 'Normal data rate for regular browsing'
    },
    'Flow Packets/s': {
        'description': 'Packet rate per second',
        'high_impact': 'Very high packet rate indicates flooding attack',
        'low_impact': 'Normal packet rate for regular traffic'
    },
    'Destination Port': {
        'description': 'Target port number',
        'ports': {
            22: 'SSH - Brute force attack target',
            80: 'HTTP - Web attack target',
            443: 'HTTPS - Web attack target',
            3389: 'RDP - Remote Desktop attack target',
            21: 'FTP - File transfer attack target'
        }
    },
    'SYN Flag Count': {
        'description': 'Number of SYN flags in the flow',
        'high_impact': 'High SYN count indicates SYN flood attack',
        'low_impact': 'Normal SYN count for connection establishment'
    },
    'RST Flag Count': {
        'description': 'Number of RST (reset) flags',
        'high_impact': 'High RST count may indicate port scanning',
        'low_impact': 'Occasional RST is normal for closed connections'
    },
    'FIN Flag Count': {
        'description': 'Number of FIN (finish) flags',
        'high_impact': 'Unusual FIN patterns may indicate attack',
        'low_impact': 'Normal FIN for proper connection termination'
    },
    'Packet Length Mean': {
        'description': 'Average size of packets in the flow',
        'high_impact': 'Very small packets often used in flooding attacks',
        'low_impact': 'Normal packet sizes for regular data transfer'
    }
}


# Feature metadata for display purposes
FEATURE_METADATA = {
    'Destination Port': {'display_unit': 'port', 'direction': 'none'},
    'Flow Duration': {'display_unit': 'μs', 'direction': 'low_is_suspicious', 'description': 'Duration of network flow'},
    'Total Fwd Packets': {'display_unit': 'packets', 'direction': 'both', 'description': 'Forward packets count'},
    'Total Backward Packets': {'display_unit': 'packets', 'direction': 'both', 'description': 'Backward packets count'},
    'Flow Bytes/s': {'display_unit': 'bytes/s', 'direction': 'high_is_suspicious', 'description': 'Data transfer rate'},
    'Flow Packets/s': {'display_unit': 'packets/s', 'direction': 'high_is_suspicious', 'description': 'Packet rate'},
}


def get_feature_baseline(feature_name, feature_index):
    """
    Get baseline statistics for a feature from scaler.
    Returns real mean from training data, not hardcoded values.
    """
    if scaler is None or not hasattr(scaler, 'mean_'):
        return None
    
    if feature_index >= len(scaler.mean_):
        return None
    
    # Get real mean from scaler (this is from training data!)
    real_mean = float(scaler.mean_[feature_index])
    real_scale = float(scaler.scale_[feature_index]) if hasattr(scaler, 'scale_') else 1.0
    
    # Get metadata for this feature
    metadata = FEATURE_METADATA.get(feature_name, {})
    
    return {
        'normal_mean': real_mean,
        'normal_std': real_scale,
        'display_unit': metadata.get('display_unit', ''),
        'direction': metadata.get('direction', 'high_is_suspicious'),
        'description': metadata.get('description', 'Network feature')
    }


def calculate_dynamic_deviation(feature_name, feature_index, observed_value):
    """
    Calculate deviation from baseline using real training data statistics.
    All values come from scaler.mean_ - no hardcoding!
    """
    baseline = get_feature_baseline(feature_name, feature_index)
    
    if baseline is None:
        return None
    
    normal_mean = baseline['normal_mean']
    
    # Avoid division by zero
    if abs(normal_mean) < 0.0001:
        return None
    
    # Calculate multiplier
    multiplier = observed_value / normal_mean if normal_mean != 0 else 1.0
    abs_multiplier = abs(multiplier)
    
    # Determine if abnormal based on direction
    direction = baseline['direction']
    is_abnormal = False
    reason_text = ''
    
    if direction == 'high_is_suspicious' and abs_multiplier >= 5:
        is_abnormal = True
        reason_text = f'Extremely high {feature_name.lower()} ({int(abs_multiplier)}x normal)'
    elif direction == 'low_is_suspicious' and abs_multiplier <= 0.2:
        is_abnormal = True
        inv_mult = int(1/abs_multiplier) if abs_multiplier > 0 else 999
        reason_text = f'Abnormally low {feature_name.lower()} ({inv_mult}x below normal)'
    elif direction == 'both' and (abs_multiplier >= 10 or abs_multiplier <= 0.1):
        is_abnormal = True
        if abs_multiplier >= 10:
            reason_text = f'Unusually high {feature_name.lower()} ({int(abs_multiplier)}x normal)'
        else:
            reason_text = f'Unusually low {feature_name.lower()}'
    
    return {
        'feature': feature_name,
        'normal_value': round(normal_mean, 2),
        'observed_value': round(observed_value, 2),
        'unit': baseline['display_unit'],
        'multiplier': round(abs_multiplier, 1),
        'is_abnormal': is_abnormal,
        'reason_text': reason_text,
        'severity': 'critical' if abs_multiplier >= 50 or abs_multiplier <= 0.02 else 'warning'
    }
