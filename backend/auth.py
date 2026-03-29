import uuid
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Blueprint, request, jsonify
from typing import Dict, Any

"""
Authentication module.
Provides JWT-based auth, login/logout endpoints, brute-force protection,
and login attempt tracking.
"""

from config import (
    logger, JWT_SECRET_KEY, JWT_EXPIRY_HOURS,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION,
    HONEYPOT_ENABLED
)
from honeypot import check_ip_reputation
from db import get_session, LoginAttemptModel, UserModel
from werkzeug.security import check_password_hash


auth_bp = Blueprint('auth', __name__)


def log_login_attempt(username: str, ip_address: str, success: bool) -> Dict[str, Any]:
    """
    Log a login attempt for security monitoring.
    
    Args:
        username: Username attempted
        ip_address: IP address of attempt
        success: Whether login was successful
    """
    attempt = {
        'id': str(uuid.uuid4()),
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'ip_address': ip_address,
        'success': success,
        'ip_reputation': check_ip_reputation(ip_address) if HONEYPOT_ENABLED else None
    }

    # Persist to database
    session = get_session()
    try:
        model = LoginAttemptModel(
            id=attempt['id'],
            timestamp=datetime.fromisoformat(attempt['timestamp']),
            username=username,
            ip_address=ip_address,
            success=success,
            payload=attempt,
        )
        session.add(model)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"Failed to persist login attempt: {exc}")
    finally:
        session.close()

    logger.info(
        f"Login attempt: {username} from {ip_address} - "
        f"{'Success' if success else 'Failed'}"
    )
    return attempt


def check_brute_force(ip_address: str, username: str) -> Dict[str, Any]:
    """
    Check if IP/username combination shows brute force pattern.
    
    Args:
        ip_address: IP address to check
        username: Username to check
    
    Returns:
        dict with brute force status and recommendations
    """
    # Count recent failed attempts from this IP (persistent storage)
    recent_cutoff = datetime.now() - timedelta(seconds=LOCKOUT_DURATION)

    session = get_session()
    try:
        try:
            recent_failures = (
                session.query(LoginAttemptModel)
                .filter(
                    LoginAttemptModel.ip_address == ip_address,
                    LoginAttemptModel.success.is_(False),
                    LoginAttemptModel.timestamp > recent_cutoff,
                )
                .all()
            )
            failure_count = len(recent_failures)
        except Exception as exc:
            # If the database is unavailable, don't break login flow.
            # The platform can still operate in a degraded mode for authentication.
            logger.error(f"Failed to query brute-force attempts: {exc}")
            failure_count = 0
    finally:
        session.close()
    
    # Determine action
    action = "allow"
    message = "Login allowed"
    
    if failure_count >= MAX_LOGIN_ATTEMPTS:
        action = "block"
        message = f"Account locked due to {failure_count} failed attempts"
    
    return {
        'failure_count': failure_count,
        'action': action,
        'message': message,
        'lockout_until': (datetime.now() + timedelta(seconds=LOCKOUT_DURATION)).isoformat() if action == "block" else None
    }


def token_required(f):
    """Decorator to protect endpoints with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            logger.warning(f"Access denied - No token provided - {request.remote_addr}")
            return jsonify({'error': 'Token is missing', 'code': 'TOKEN_MISSING'}), 401
        
        try:
            # Decode the token
            data = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            current_user = data['username']
        except pyjwt.ExpiredSignatureError:
            logger.warning(f"Access denied - Token expired - {request.remote_addr}")
            return jsonify({'error': 'Token has expired', 'code': 'TOKEN_EXPIRED'}), 401
        except pyjwt.InvalidTokenError:
            logger.warning(f"Access denied - Invalid token - {request.remote_addr}")
            return jsonify({'error': 'Invalid token', 'code': 'TOKEN_INVALID'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Login endpoint - returns JWT token with brute force protection"""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No credentials provided'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Get client IP
    client_ip = request.remote_addr or '127.0.0.1'
    
    # Check for brute force attempts
    brute_force_check = check_brute_force(client_ip, username)
    
    if brute_force_check['action'] == 'block':
        # Log blocked attempt
        log_login_attempt(username, client_ip, False)
        
        return jsonify({
            'error': 'Account temporarily locked',
            'message': brute_force_check['message'],
            'lockout_until': brute_force_check['lockout_until'],
            'blocked': True
        }), 403
    
    # Check credentials securely
    session = get_session()
    user = session.query(UserModel).filter(UserModel.username == username).first()
    session.close()

    if user and check_password_hash(user.password_hash, password):
        # Successful login
        log_login_attempt(username, client_ip, True)
        
        # Generate JWT token
        token = pyjwt.encode({
            'username': username,
            'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)
        }, JWT_SECRET_KEY, algorithm='HS256')
        
        logger.info(f"User logged in: {username} from {client_ip}")
        
        return jsonify({
            'success': True,
            'token': token,
            'username': username,
            'expires_in': JWT_EXPIRY_HOURS * 3600
        })
    else:
        # Failed login
        log_login_attempt(username, client_ip, False)
        
        logger.warning(f"Failed login attempt for user: {username} from {client_ip}")
        
        # Return failure with brute force info
        response_data = {
            'error': 'Invalid credentials',
            'failure_count': brute_force_check['failure_count'] + 1,
            'blocked': False
        }
        
        return jsonify(response_data), 401


@auth_bp.route('/api/auth/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Logout endpoint - invalidates token (client should discard token)"""
    logger.info(f"User logged out: {current_user}")
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@auth_bp.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    """Verify if token is valid"""
    return jsonify({
        'valid': True,
        'username': current_user

    })


@auth_bp.route('/api/login-attempts', methods=['GET'])
@token_required
def get_login_attempts(current_user):
    """Get login attempts for security monitoring"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 20, type=int)

    # Get filter parameters
    success_filter = request.args.get('success', None)
    ip_filter = request.args.get('ip', None)

    session = get_session()
    try:
        try:
            query = session.query(LoginAttemptModel)
        except Exception as exc:
            logger.error(f"Database unavailable for login attempts: {exc}")
            return jsonify({'error': 'Database unavailable'}), 503

        if success_filter is not None:
            success_bool = success_filter.lower() == 'true'
            query = query.filter(LoginAttemptModel.success.is_(success_bool))

        if ip_filter:
            query = query.filter(LoginAttemptModel.ip_address == ip_filter)

        query = query.order_by(LoginAttemptModel.timestamp.desc())

        total = query.count()
        page_attempts = (
            query.offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        attempts_payload = []
        for attempt in page_attempts:
            # Ensure we always return a dict compatible with previous in-memory structure
            if attempt.payload:
                attempts_payload.append(attempt.payload)
            else:
                attempts_payload.append(
                    {
                        'id': attempt.id,
                        'timestamp': attempt.timestamp.isoformat(),
                        'username': attempt.username,
                        'ip_address': attempt.ip_address,
                        'success': attempt.success,
                    }
                )

        return jsonify({
            'attempts': attempts_payload,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size
        })
    finally:
        session.close()
