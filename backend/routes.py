import os
import json
from datetime import datetime
from flask import Blueprint, request, jsonify

"""
API routes for the IDS backend.
Implements detection, telemetry, and analytics endpoints.
"""

from config import (
    logger, MODELS_FOLDER,
    BATCH_SIZE, MIN_DETECTIONS, MAX_DETECTIONS,
    HONEYPOT_ENABLED, HONEYPOT_API_KEY
)
from models_loader import (
    rf_model, xgb_model, iso_model,
    label_mapping, feature_list,
    shap_explainer, SHAP_AVAILABLE,
    sample_data
)
from auth import token_required
from honeypot import ip_reputation_cache
from detection import generate_real_detection
from db import get_session, DetectionModel, FeedbackModel, LoginAttemptModel


api_bp = Blueprint('api', __name__)


@api_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'models_loaded': {
            'random_forest': rf_model is not None,
            'xgboost': xgb_model is not None,
            'isolation_forest': iso_model is not None
        },
        'shap_available': SHAP_AVAILABLE and shap_explainer is not None,
        'data_loaded': sample_data is not None,
        'timestamp': datetime.now().isoformat()
    })

# --- Detection Endpoints ---

@api_bp.route('/api/detections', methods=['GET'])
def get_detections():
    """Get detections with pagination and filtering"""
    session = get_session()

    try:
        # Ensure we have at least MIN_DETECTIONS in the database by generating new ones
        current_count = session.query(DetectionModel).count()
        while current_count < MIN_DETECTIONS:
            detection = generate_real_detection()
            if detection:
                model = DetectionModel(
                    id=detection['detection_id'],
                    timestamp=datetime.fromisoformat(detection['timestamp']),
                    prediction=detection['prediction'],
                    attack_type=detection.get('attack_type'),
                    severity=detection.get('severity'),
                    risk_score=detection.get('risk_score'),
                    combined_risk_score=detection.get('combined_risk_score'),
                    ip_address=detection.get('ip_address'),
                    payload=detection,
                )
                session.add(model)
                session.commit()
                current_count += 1
            else:
                break

        # Get query parameters for filtering
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 20, type=int)
        severity = request.args.get('severity', None)
        attack_type = request.args.get('attack_type', None)
        prediction = request.args.get('prediction', None)
        min_risk_score = request.args.get('min_risk_score', None, type=float)
        max_risk_score = request.args.get('max_risk_score', None, type=float)

        # Limit page size
        page_size = min(page_size, 100)

        query = session.query(DetectionModel)

        if severity:
            query = query.filter(DetectionModel.severity.ilike(severity))

        if attack_type:
            like_pattern = f"%{attack_type}%"
            query = query.filter(DetectionModel.attack_type.ilike(like_pattern))

        if prediction:
            query = query.filter(DetectionModel.prediction == prediction.upper())

        if min_risk_score is not None:
            query = query.filter(DetectionModel.risk_score >= min_risk_score)

        if max_risk_score is not None:
            query = query.filter(DetectionModel.risk_score <= max_risk_score)

        total = query.count()
        total_pages = (total + page_size - 1) // page_size

        detections_models = (
            query.order_by(DetectionModel.timestamp.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        detections = []
        for m in detections_models:
            if m.payload:
                detections.append(m.payload)
            else:
                detections.append(
                    {
                        'detection_id': m.id,
                        'timestamp': m.timestamp.isoformat(),
                        'prediction': m.prediction,
                        'attack_type': m.attack_type,
                        'risk_score': m.risk_score,
                        'severity': m.severity,
                        'combined_risk_score': m.combined_risk_score,
                        'ip_address': m.ip_address,
                    }
                )

        return jsonify({
            'detections': detections,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages,
            'using_real_models': True
        })
    finally:
        session.close()


@api_bp.route('/api/detections/generate', methods=['POST'])
def generate_detections():
    """Generate new batch of detections"""
    session = get_session()
    try:
        count = request.json.get('count', BATCH_SIZE) if request.json else BATCH_SIZE
        count = min(count, MAX_DETECTIONS)

        new_detections = []
        for _ in range(count):
            detection = generate_real_detection()
            if detection:
                model = DetectionModel(
                    id=detection['detection_id'],
                    timestamp=datetime.fromisoformat(detection['timestamp']),
                    prediction=detection['prediction'],
                    attack_type=detection.get('attack_type'),
                    severity=detection.get('severity'),
                    risk_score=detection.get('risk_score'),
                    combined_risk_score=detection.get('combined_risk_score'),
                    ip_address=detection.get('ip_address'),
                    payload=detection,
                )
                session.add(model)
                new_detections.append(detection)

        session.commit()

        # Enforce MAX_DETECTIONS cap by removing oldest records
        total = session.query(DetectionModel).count()
        if total > MAX_DETECTIONS:
            excess = total - MAX_DETECTIONS
            oldest = (
                session.query(DetectionModel)
                .order_by(DetectionModel.timestamp.asc())
                .limit(excess)
                .all()
            )
            for record in oldest:
                session.delete(record)
            session.commit()

        total_after = session.query(DetectionModel).count()

        return jsonify({
            'generated': len(new_detections),
            'total': total_after,
            'using_real_models': True
        })
    finally:
        session.close()


@api_bp.route('/api/detections/<detection_id>', methods=['DELETE'])
def delete_detection(detection_id):
    """Delete a specific detection (analyst feedback)"""
    session = get_session()
    try:
        deleted = (
            session.query(DetectionModel)
            .filter(DetectionModel.id == detection_id)
            .delete()
        )
        session.commit()

        if deleted:
            return jsonify({'success': True, 'message': 'Detection removed'})
        else:
            return jsonify({'success': False, 'message': 'Detection not found'}), 404
    finally:
        session.close()


@api_bp.route('/api/detections/<detection_id>', methods=['GET'])
def get_detection_by_id(detection_id):
    """Get a single detection by ID with full details"""
    session = get_session()
    try:
        detection_model = (
            session.query(DetectionModel)
            .filter(DetectionModel.id == detection_id)
            .first()
        )
        if not detection_model:
            return jsonify({'error': 'Detection not found'}), 404

        detection_payload = detection_model.payload or {
            'detection_id': detection_model.id,
            'timestamp': detection_model.timestamp.isoformat(),
            'prediction': detection_model.prediction,
            'attack_type': detection_model.attack_type,
            'risk_score': detection_model.risk_score,
            'severity': detection_model.severity,
            'combined_risk_score': detection_model.combined_risk_score,
            'ip_address': detection_model.ip_address,
        }

        feedback_models = (
            session.query(FeedbackModel)
            .filter(FeedbackModel.detection_id == detection_id)
            .order_by(FeedbackModel.timestamp.desc())
            .all()
        )
        feedback_history = [
            fb.payload
            if fb.payload
            else {
                'feedback_id': fb.id,
                'detection_id': fb.detection_id,
                'label': fb.label,
                'user': fb.user,
                'timestamp': fb.timestamp.isoformat(),
            }
            for fb in feedback_models
        ]

        return jsonify({
            'detection': detection_payload,
            'feedback': feedback_history
        })
    finally:
        session.close()

# --- Feedback & HITL ---

@api_bp.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit analyst feedback for a detection (Human-in-the-Loop)"""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    detection_id = data.get('detection_id')
    label = data.get('label')  # 'ATTACK', 'BENIGN', or 'Unknown'
    note = data.get('note', '')
    user = data.get('user', 'analyst')
    
    if not detection_id or not label:
        return jsonify({'error': 'detection_id and label are required'}), 400
    
    if label not in ['ATTACK', 'BENIGN', 'Unknown']:
        return jsonify({'error': 'label must be ATTACK, BENIGN, or Unknown'}), 400
    
    session = get_session()
    try:
        # Check if detection exists
        detection_model = (
            session.query(DetectionModel)
            .filter(DetectionModel.id == detection_id)
            .first()
        )
        if not detection_model:
            return jsonify({'error': 'Detection not found'}), 404

        # Create feedback entry
        import uuid
        feedback_id = str(uuid.uuid4())
        feedback_entry = {
            'feedback_id': feedback_id,
            'detection_id': detection_id,
            'label': label,
            'note': note,
            'user': user,
            'timestamp': datetime.now().isoformat()
        }

        feedback_model = FeedbackModel(
            id=feedback_id,
            detection_id=detection_id,
            timestamp=datetime.fromisoformat(feedback_entry['timestamp']),
            label=label,
            user=user,
            payload=feedback_entry,
        )
        session.add(feedback_model)
        session.commit()

        return jsonify({
            'success': True,
            'feedback_id': feedback_id,
            'message': f'Feedback recorded: {label}'
        })
    finally:
        session.close()


@api_bp.route('/api/detections/clear', methods=['DELETE'])
def clear_detections():
    """Clear all detections"""
    session = get_session()
    try:
        deleted = session.query(DetectionModel).delete()
        session.commit()
        logger.info(f"Cleared {deleted} detections from database.")
        return jsonify({'success': True, 'message': 'All detections cleared'})
    finally:
        session.close()

# --- Dashboard Statistics ---

@api_bp.route('/api/stats', methods=['GET'])
def get_stats():
    """Get detection statistics"""
    session = get_session()
    try:
        all_detections = session.query(DetectionModel).all()
        if not all_detections:
            return jsonify({
                'total_detections': 0,
                'by_severity': {},
                'by_attack_type': {},
                'attack_rate': 0
            })

        by_severity = {}
        by_attack_type = {}
        attack_count = 0

        for m in all_detections:
            payload = m.payload or {}
            sev = payload.get('severity', m.severity or 'Unknown')
            by_severity[sev] = by_severity.get(sev, 0) + 1

            att = payload.get('attack_type', m.attack_type or 'Unknown')
            by_attack_type[att] = by_attack_type.get(att, 0) + 1

            if payload.get('prediction', m.prediction) == 'ATTACK':
                attack_count += 1

        total = len(all_detections)

        return jsonify({
            'total_detections': total,
            'by_severity': by_severity,
            'by_attack_type': by_attack_type,
            'attack_rate': round(attack_count / total, 3) if total else 0,
            'using_real_models': True
        })
    finally:
        session.close()


@api_bp.route('/api/model/info', methods=['GET'])
def get_model_info():
    """Get information about loaded models"""
    from config import WEIGHT_RF, WEIGHT_XGB, WEIGHT_ISO
    return jsonify({
        'models': {
            'random_forest': {
                'loaded': rf_model is not None,
                'type': str(type(rf_model).__name__) if rf_model else None,
                'weight': WEIGHT_RF
            },
            'xgboost': {
                'loaded': xgb_model is not None,
                'type': str(type(xgb_model).__name__) if xgb_model else None,
                'weight': WEIGHT_XGB
            },
            'isolation_forest': {
                'loaded': iso_model is not None,
                'type': str(type(iso_model).__name__) if iso_model else None,
                'weight': WEIGHT_ISO
            }
        },
        'shap_explainer': shap_explainer is not None,
        'feature_count': len(feature_list),
        'class_count': len(label_mapping),
        'classes': label_mapping
    })

# --- Honeypot Analytics ---

@api_bp.route('/api/honeypot/stats', methods=['GET'])
@token_required
def get_honeypot_stats(current_user):
    """Get honeypot statistics for dashboard"""
    session = get_session()
    try:
        # Get unique IPs currently in detections database
        detection_models = session.query(DetectionModel).all()
        active_ips = set(
            (m.payload or {}).get('ip_address', m.ip_address)
            for m in detection_models
            if (m.payload or {}).get('ip_address', m.ip_address)
        )

        # Calculate IP reputation statistics based ONLY on active detections
        total_checks = len(active_ips)
    
    threat_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'clean': 0
    }
    
    malicious_ips = []
    
        # Analyze reputation data for active IPs only
        for ip in active_ips:
            # Get from cache
            reputation_entry = ip_reputation_cache.get(ip)
            if reputation_entry:
                reputation, timestamp = reputation_entry
                threat_level = reputation.get('threat_level', 'Clean')

                if threat_level == 'Critical':
                    threat_counts['critical'] += 1
                    malicious_ips.append({
                        'ip': ip,
                        'threat_score': reputation.get('threat_score', 0),
                        'threat_level': threat_level,
                        'visitor_types': reputation.get('visitor_types', [])
                    })
                elif threat_level == 'High':
                    threat_counts['high'] += 1
                    malicious_ips.append({
                        'ip': ip,
                        'threat_score': reputation.get('threat_score', 0),
                        'threat_level': threat_level,
                        'visitor_types': reputation.get('visitor_types', [])
                    })
                elif threat_level == 'Medium':
                    threat_counts['medium'] += 1
                elif threat_level == 'Low':
                    threat_counts['low'] += 1
                else:
                    threat_counts['clean'] += 1
            else:
                # If not in cache for some reason (shouldn't happen), count as clean
                threat_counts['clean'] += 1

        # Sort malicious IPs by threat score
        malicious_ips.sort(key=lambda x: x['threat_score'], reverse=True)

        # Calculate login statistics from database
        login_query = session.query(LoginAttemptModel)
        total_login_attempts = login_query.count()
        failed_attempts = (
            login_query.filter(LoginAttemptModel.success.is_(False)).count()
        )
        successful_logins = total_login_attempts - failed_attempts

        recent_models = (
            login_query.order_by(LoginAttemptModel.timestamp.desc())
            .limit(10)
            .all()
        )
        recent_attempts = []
        for m in recent_models:
            if m.payload:
                recent_attempts.append(m.payload)
            else:
                recent_attempts.append(
                    {
                        'id': m.id,
                        'timestamp': m.timestamp.isoformat(),
                        'username': m.username,
                        'ip_address': m.ip_address,
                        'success': m.success,
                    }
                )

        return jsonify({
            'ip_reputation': {
                'total_checks': total_checks,
                'threats_found': threat_counts['critical'] + threat_counts['high'] + threat_counts['medium'],
                'threat_distribution': threat_counts,
                'malicious_ips': malicious_ips[:10],  # Top 10 most dangerous
            },
            'login_monitoring': {
                'total_attempts': total_login_attempts,
                'failed_attempts': failed_attempts,
                'successful_logins': successful_logins,
                'recent_attempts': recent_attempts
            },
            'honeypot_status': {
                'enabled': HONEYPOT_ENABLED,
                'api_key_configured': bool(HONEYPOT_API_KEY),
                'cache_size': total_checks
            }
        })
    finally:
        session.close()

# --- Advanced Analytics ---

@api_bp.route('/api/analytics/trends', methods=['GET'])
def get_trends():
    """Get time-series detection trends"""
    session = get_session()
    try:
        all_detections = session.query(DetectionModel).all()
        if not all_detections:
            return jsonify({'trends': [], 'message': 'No detections available'})

        # Group detections by date
        trends = {}
        for m in all_detections:
            try:
                payload = m.payload or {}
                timestamp = payload.get('timestamp') or m.timestamp.isoformat()
                date = timestamp.split('T')[0] if 'T' in timestamp else timestamp[:10]

                if date not in trends:
                    trends[date] = {
                        'date': date,
                        'total': 0,
                        'attacks': 0,
                        'benign': 0,
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0
                    }

                trends[date]['total'] += 1

                prediction = payload.get('prediction', m.prediction)
                if prediction == 'ATTACK':
                    trends[date]['attacks'] += 1
                else:
                    trends[date]['benign'] += 1

                severity = (payload.get('severity') or m.severity or 'Low').lower()
                if severity in trends[date]:
                    trends[date][severity] += 1
            except Exception:
                continue

        # Convert to sorted list
        trend_list = sorted(trends.values(), key=lambda x: x['date'])

        return jsonify({
            'trends': trend_list,
            'total_days': len(trend_list)
        })
    finally:
        session.close()


@api_bp.route('/api/analytics/attack-types', methods=['GET'])
def get_attack_types():
    """Get attack type distribution"""
    session = get_session()
    try:
        all_detections = session.query(DetectionModel).all()
        if not all_detections:
            return jsonify({'attack_types': {}, 'total': 0})

        attack_types = {}
        for m in all_detections:
            payload = m.payload or {}
            attack_type = payload.get('attack_type', m.attack_type or 'Unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        # Sort by count descending
        sorted_types = dict(sorted(attack_types.items(), key=lambda x: x[1], reverse=True))

        return jsonify({
            'attack_types': sorted_types,
            'total': len(all_detections)
        })
    finally:
        session.close()


@api_bp.route('/api/analytics/feedback-stats', methods=['GET'])
def get_feedback_stats():
    """Get HITL feedback statistics"""
    session = get_session()
    try:
        feedback_models = session.query(FeedbackModel).all()

        total_feedback = 0
        label_counts = {'ATTACK': 0, 'BENIGN': 0, 'Unknown': 0}

        for fb in feedback_models:
            payload = fb.payload or {}
            label = payload.get('label', fb.label or 'Unknown')
            total_feedback += 1
            if label in label_counts:
                label_counts[label] += 1

        # Calculate percentages
        percentages = {}
        for label, count in label_counts.items():
            percentages[label] = round(count / total_feedback * 100, 2) if total_feedback > 0 else 0

        detections_with_feedback = (
            session.query(FeedbackModel.detection_id)
            .distinct()
            .count()
        )

        return jsonify({
            'total_feedback': total_feedback,
            'label_counts': label_counts,
            'percentages': percentages,
            'detections_with_feedback': detections_with_feedback
        })
    finally:
        session.close()


@api_bp.route('/api/analytics/metrics', methods=['GET'])
def get_metrics():
    """Get model performance metrics"""
    # Load training report if available
    try:
        report_path = os.path.join(MODELS_FOLDER, 'training_report_v1.json')
        with open(report_path, 'r') as f:
            training_report = json.load(f)
        
        return jsonify({
            'training_date': training_report.get('training_date'),
            'models_trained': training_report.get('models_trained', []),
            'evaluation_results': training_report.get('evaluation_results', {}),
            'cross_validation': training_report.get('cross_validation', {}),
            'available': True
        })
    except Exception as e:
        logger.warning(f"Could not load training report: {e}")
        return jsonify({
            'available': False,
            'message': 'Training report not available'
        })
