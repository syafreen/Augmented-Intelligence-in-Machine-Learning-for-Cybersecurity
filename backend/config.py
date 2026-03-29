import os
import sys
import logging
import secrets

"""
Configuration module.
Loads config.yaml and exposes configuration constants and a shared logger.
"""
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
MODELS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
DATA_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
LOGS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


try:
    import yaml
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
    print(f"[OK] Loaded configuration from {CONFIG_PATH}")
except Exception as e:
    print(f"[ERROR] Failed to load config: {e}")
    config = {}


# Ensemble weights
weights_config = config.get('weights', {})
WEIGHT_XGB = weights_config.get('xgb', 0.5)
WEIGHT_RF = weights_config.get('rf', 0.3)
WEIGHT_ISO = weights_config.get('iso', 0.2)

# Severity thresholds
thresholds = config.get('thresholds', {})
THRESHOLD_CRITICAL = thresholds.get('critical', 0.85)
THRESHOLD_HIGH = thresholds.get('high', 0.70)
THRESHOLD_MEDIUM = thresholds.get('medium', 0.55)

# Severity mapping
severity_mapping = config.get('severity_mapping', {})

# Detection settings
detection_config = config.get('detection', {})
BATCH_SIZE = detection_config.get('batch_size', 30)
MIN_DETECTIONS = detection_config.get('min_detections', 20)
MAX_DETECTIONS = detection_config.get('max_detections', 50)

app_config = config.get('app', {})
API_PORT = int(os.getenv("IDS_API_PORT", app_config.get('port', 8081)))
API_HOST = os.getenv("IDS_API_HOST", app_config.get('host', '127.0.0.1'))

_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_SQLITE = f"sqlite:///{os.path.join(_DB_DIR, 'ids_local.db')}"

database_config = config.get('database', {})

DATABASE_URL = os.getenv(
    "IDS_DATABASE_URL",
    database_config.get(
        'url',
        _DEFAULT_SQLITE
    )
)

auth_config = config.get('auth', {})
_env_jwt = os.getenv("IDS_JWT_SECRET_KEY", auth_config.get('secret_key'))
if not _env_jwt or _env_jwt == 'change-this-jwt-secret':
    JWT_SECRET_KEY = secrets.token_hex(32)
else:
    JWT_SECRET_KEY = _env_jwt
JWT_EXPIRY_HOURS = auth_config.get('token_expiry_hours', 24)

ADMIN_USERNAME = os.getenv(
    "IDS_ADMIN_USERNAME",
    auth_config.get('admin_username', 'admin')
)
ADMIN_PASSWORD = os.getenv(
    "IDS_ADMIN_PASSWORD",
    auth_config.get('admin_password', 'admin123')
)

honeypot_config = config.get('honeypot', {})
HONEYPOT_ENABLED = honeypot_config.get('enabled', False)
HONEYPOT_API_KEY = os.getenv(
    "IDS_HONEYPOT_API_KEY",
    honeypot_config.get('api_key', '')
)
HONEYPOT_CACHE_DURATION = honeypot_config.get('cache_duration', 3600)
HONEYPOT_TIMEOUT = honeypot_config.get('timeout', 5)
HONEYPOT_THRESHOLDS = honeypot_config.get('threat_thresholds', {})

# Security settings
security_config = config.get('security', {})
MAX_LOGIN_ATTEMPTS = security_config.get('max_login_attempts', 5)
LOCKOUT_DURATION = security_config.get('lockout_duration', 900)


os.makedirs(LOGS_FOLDER, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_FOLDER, 'api.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ids-backend')
logger.info("IDS API server starting...")
