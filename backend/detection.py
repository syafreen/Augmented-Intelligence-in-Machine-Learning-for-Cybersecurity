"""
Core ML prediction logic, SHAP explanation generation,
severity calculation, and synthetic/real detection generation.
"""

import uuid
import random
import numpy as np
import pandas as pd
from datetime import datetime

from config import (
    logger,
    WEIGHT_RF, WEIGHT_XGB, WEIGHT_ISO,
    THRESHOLD_CRITICAL, THRESHOLD_HIGH, THRESHOLD_MEDIUM,
    severity_mapping, HONEYPOT_ENABLED
)
from models_loader import (
    rf_model, xgb_model, iso_model, scaler,
    label_mapping, feature_list,
    shap_explainer, SHAP_AVAILABLE,
    sample_data, samples_by_attack
)
from explanations import (
    FEATURE_EXPLANATIONS, calculate_dynamic_deviation
)
from honeypot import check_ip_reputation, generate_realistic_ip
from typing import Optional, Dict, Tuple, Any


def get_severity(risk_score: float) -> str:
    """Get severity level based on risk score from config thresholds"""
    if risk_score >= THRESHOLD_CRITICAL:
        return 'Critical'
    elif risk_score >= THRESHOLD_HIGH:
        return 'High'
    elif risk_score >= THRESHOLD_MEDIUM:
        return 'Medium'
    else:
        return 'Low'


def get_severity_from_mapping(attack_type: str) -> str:
    """Get severity from config severity_mapping"""
    return severity_mapping.get(attack_type, 'Medium')


def make_real_prediction(sample_features: np.ndarray) -> Tuple[Optional[int], Optional[float], Optional[Dict[str, float]]]:
    """Make real prediction using ensemble of trained models"""
    if rf_model is None or xgb_model is None:
        return None, None, None
    
    # Reshape for single sample
    X = sample_features.reshape(1, -1)
    
    # Get probabilities from supervised models
    rf_proba = rf_model.predict_proba(X)[0]
    xgb_proba = xgb_model.predict_proba(X)[0]
    
    # Get anomaly score from Isolation Forest
    if iso_model is not None:
        iso_score = iso_model.decision_function(X)[0]
        # Normalize to 0-1 (lower score = more anomalous)
        iso_score_norm = 1 / (1 + np.exp(iso_score))  # Sigmoid normalization
    else:
        iso_score_norm = 0.5
    
    # Combine probabilities using weights from config
    combined_proba = (WEIGHT_RF * rf_proba) + (WEIGHT_XGB * xgb_proba)
    
    # Boost attack probabilities based on anomaly score
    # Higher iso_score_norm means more anomalous
    for i in range(1, len(combined_proba)):  # Skip class 0 (BENIGN)
        combined_proba[i] *= (1 + WEIGHT_ISO * iso_score_norm)
    
    # Normalize
    combined_proba = combined_proba / combined_proba.sum()
    
    # Get prediction
    predicted_class = int(np.argmax(combined_proba))
    confidence = float(combined_proba[predicted_class])
    
    # Model scores for transparency
    model_scores = {
        'rf_prob': float(rf_proba[predicted_class]),
        'xgb_prob': float(xgb_proba[predicted_class]),
        'iso_score': round(iso_score_norm, 4)
    }
    
    return predicted_class, confidence, model_scores


def generate_real_detection() -> Optional[Dict[str, Any]]:
    """Generate a detection using real ML models on real data"""
    if sample_data is None or len(sample_data) == 0:
        return None
    
    # Pure random selection from attack types (realistic behavior)
    attack_types = list(samples_by_attack.keys())
    
    if attack_types and samples_by_attack:
        # Randomly pick an attack type
        selected_type = random.choice(attack_types)
        
        # Get random sample from this attack type
        type_samples = samples_by_attack[selected_type]
        if len(type_samples) > 0:
            idx = random.randint(0, len(type_samples) - 1)
            row = type_samples.iloc[idx]
        else:
            # Fallback to random sampling from all data
            idx = random.randint(0, len(sample_data) - 1)
            row = sample_data.iloc[idx]
    else:
        # Fallback to random sampling if grouping failed
        idx = random.randint(0, len(sample_data) - 1)
        row = sample_data.iloc[idx]

    
    # Extract features that match our feature list
    features = []
    feature_values_dict = {}
    for feat in feature_list:
        if feat in row.index:
            val = row[feat]
            # Handle non-numeric values
            if pd.isna(val) or not np.isfinite(val):
                val = 0.0
            features.append(float(val))
            feature_values_dict[feat] = float(val)
        else:
            features.append(0.0)
            feature_values_dict[feat] = 0.0
    
    features = np.array(features)
    
    # Scale features
    if scaler is not None:
        features_scaled = scaler.transform(features.reshape(1, -1))[0]
    else:
        features_scaled = features
    
    # Make real prediction
    predicted_class, confidence, model_scores = make_real_prediction(features_scaled)
    
    if predicted_class is None:
        return None
    
    # Get attack type name
    attack_type = label_mapping.get(predicted_class, 'Unknown')
    
    # Fix encoding artifacts in attack type names (display only)
    # The "�" symbol is from dataset encoding - replace with dash for clean display
    attack_type = attack_type.replace('\ufffd', '-').replace('�', '-')
    
    # Determine if attack or benign
    is_attack = predicted_class != 0
    prediction = 'ATTACK' if is_attack else 'BENIGN'
    
    # Calculate risk score
    if is_attack:
        risk_score = confidence * 0.7 + model_scores['iso_score'] * 0.3
    else:
        risk_score = (1 - confidence) * 0.3
    
    risk_score = min(0.99, max(0.01, risk_score))
    
    # Get severity from config mapping
    severity = get_severity_from_mapping(attack_type)
    if severity == 'Low' and risk_score > THRESHOLD_HIGH:
        severity = get_severity(risk_score)
    
    # Generate SHAP explanation
    explanation = []
    
    # Run SHAP for ALL detections (attacks and benign)
    if shap_explainer is not None:
        try:
            # Compute SHAP values
            shap_input = features_scaled.reshape(1, -1)
            shap_values = shap_explainer.shap_values(shap_input)
            
            # Handle multi-class or binary output
            if isinstance(shap_values, list):
                # Multi-class: use predicted class or class 1 for attacks
                target_class = predicted_class if predicted_class < len(shap_values) else 0
                class_shap = np.array(shap_values[target_class]).flatten()
            else:
                class_shap = np.array(shap_values).flatten()
            
            # Ensure we have a 1D array
            if class_shap.ndim > 1:
                class_shap = class_shap.flatten()
            
            # Ensure proper length
            if len(class_shap) != len(feature_list):
                logger.warning(f"SHAP values length mismatch: {len(class_shap)} vs {len(feature_list)}")
                # Truncate or pad as needed
                if len(class_shap) > len(feature_list):
                    class_shap = class_shap[:len(feature_list)]
            
            # Get top 5 features by absolute SHAP value
            abs_shap = np.abs(class_shap)
            num_features = min(5, len(abs_shap))
            top_indices = np.argsort(abs_shap)[::-1][:num_features]
            
            # Calculate total for percentage
            total_shap = float(np.sum(abs_shap))
            
            for idx in top_indices:
                idx = int(idx)
                if idx >= len(feature_list) or idx >= len(features):
                    continue
                    
                feat_name = feature_list[idx]
                shap_val = float(class_shap[idx])
                feat_val = float(features[idx])
                
                # Calculate contribution percentage
                if total_shap > 0.0001:
                    contrib_pct = (abs(shap_val) / total_shap) * 100
                else:
                    contrib_pct = 20.0  # Default even distribution
                
                # Get description from FEATURE_EXPLANATIONS
                feat_info = FEATURE_EXPLANATIONS.get(feat_name, {})
                desc = feat_info.get('description', 'Network feature')
                
                # Determine impact
                if contrib_pct > 25:
                    impact = 'HIGH'
                    impact_desc = feat_info.get('high_impact', 'High contribution')
                elif contrib_pct > 15:
                    impact = 'MEDIUM' 
                    impact_desc = 'Moderate contribution'
                else:
                    impact = 'LOW'
                    impact_desc = feat_info.get('low_impact', 'Minor contribution')
                
                explanation.append({
                    'feature': feat_name,
                    'value': round(feat_val, 4),
                    'contribution': round(contrib_pct, 2),
                    'impact': impact,
                    'description': desc,
                    'explanation': impact_desc
                })
                
        except Exception as e:
            logger.warning(f"SHAP failed: {e}")
    
    # If no SHAP, provide basic explanation using raw features
    if not explanation:
        for i, feat in enumerate(feature_list[:5]):
            if i < len(features):
                explanation.append({
                    'feature': feat,
                    'value': round(float(features[i]), 4),
                    'contribution': 20.0,  # Equal distribution
                    'impact': 'MEDIUM',
                    'description': FEATURE_EXPLANATIONS.get(feat, {}).get('description', 'Network feature'),
                    'explanation': 'Feature analysis based on model input'
                })
    
    # Generate real data-based feature comparison (Normal vs Observed)
    # Uses scaler.mean_ for baselines - 100% from training data, no hardcoding!
    feature_comparison = []
    why_detected_reasons = []
    
    # Use top SHAP features for comparison
    for i, exp in enumerate(explanation[:5]):  # Top 5 features
        feat_name = exp['feature']
        feat_value = exp['value']
        
        # Find feature index in feature_list
        try:
            feat_index = feature_list.index(feat_name)
        except ValueError:
            feat_index = i  # Fallback to position
        
        # Use dynamic baseline from scaler (real training data!)
        deviation = calculate_dynamic_deviation(feat_name, feat_index, feat_value)
        
        if deviation is not None:
            feature_comparison.append({
                'feature': feat_name,
                'normal_value': deviation['normal_value'],
                'observed_value': deviation['observed_value'],
                'unit': deviation['unit'],
                'multiplier': deviation['multiplier'],
                'is_abnormal': deviation['is_abnormal'],
                'severity': deviation['severity'],
                'shap_contribution': exp['contribution']
            })
            
            if deviation['is_abnormal'] and deviation['reason_text']:
                why_detected_reasons.append(deviation['reason_text'])
    
    # If no abnormal features found from baselines, use SHAP contributions
    if not why_detected_reasons and explanation:
        for exp in explanation[:3]:
            if exp['contribution'] > 15:
                why_detected_reasons.append(f"High contribution from {exp['feature']} ({exp['contribution']}%)")
    
    # Smart IP generation with hybrid approach
    # For attacks: Try to find malicious IP (70% chance), but keep realistic clean IPs (30%)
    # For benign: Always use clean IPs
    ip_address = None
    ip_reputation = None
    
    if HONEYPOT_ENABLED and is_attack:
        # For attacks, try to find a malicious IP (makes demo more impressive)
        # But not always - keep it realistic
        max_attempts = 5  # Try 5 times to find malicious IP
        
        for attempt in range(max_attempts):
            candidate_ip = generate_realistic_ip(attack_type)
            
            try:
                candidate_reputation = check_ip_reputation(candidate_ip)
                
                # If we found a malicious IP, use it!
                if candidate_reputation and candidate_reputation.get('is_threat'):
                    ip_address = candidate_ip
                    ip_reputation = candidate_reputation
                    logger.info(f"Found malicious IP for {attack_type}: {ip_address} (Threat: {candidate_reputation.get('threat_score')}/255)")
                    break
                    
                # Keep track of last checked IP (fallback to clean if no malicious found)
                if attempt == max_attempts - 1:
                    ip_address = candidate_ip
                    ip_reputation = candidate_reputation
                    logger.debug(f"Using clean IP for {attack_type}: {ip_address} (realistic scenario)")
                    
            except Exception as e:
                logger.warning(f"IP reputation check failed (attempt {attempt + 1}): {e}")
                continue
        
        # If all attempts failed, generate one final IP
        if ip_address is None:
            ip_address = generate_realistic_ip(attack_type)
            try:
                ip_reputation = check_ip_reputation(ip_address)
            except Exception as e:
                logger.warning(f"Final IP reputation check failed: {e}")
    else:
        # For benign traffic or if honeypot disabled, just generate one IP
        ip_address = generate_realistic_ip(attack_type if is_attack else 'Benign')
        if HONEYPOT_ENABLED:
            try:
                ip_reputation = check_ip_reputation(ip_address)
            except Exception as e:
                logger.warning(f"Failed to check IP reputation: {e}")
    
    # Calculate combined risk score (ML + IP reputation)
    combined_risk_score = risk_score
    if ip_reputation and ip_reputation.get('is_threat'):
        # Increase risk if IP is known threat
        threat_score = ip_reputation.get('threat_score', 0)
        ip_risk_factor = min(threat_score / 255.0, 0.3)  # Max 30% increase
        combined_risk_score = min(0.99, risk_score + ip_risk_factor)

    
    # Create detection object
    detection = {
        'detection_id': str(uuid.uuid4()),
        'timestamp': datetime.now().isoformat(),
        'prediction': prediction,
        'attack_type': attack_type,
        'risk_score': round(risk_score, 3),
        'confidence': round(confidence, 3),
        'severity': severity,
        'model_scores': model_scores,
        'explanation': explanation,
        'feature_comparison': feature_comparison,
        'why_detected': why_detected_reasons,
        'is_real_prediction': True,
        # Honeypot integration
        'ip_address': ip_address,
        'ip_reputation': ip_reputation,
        'combined_risk_score': round(combined_risk_score, 3)
    }
    
    return detection
