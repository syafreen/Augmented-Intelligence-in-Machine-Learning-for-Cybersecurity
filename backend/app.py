"""
Main application entry point. 
Initializes the Flask server, registers CORS, and binds route blueprints.
"""

from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from config import logger, API_PORT, API_HOST
from db import init_db

# Trigger model pre-loading
from models_loader import (
    rf_model, xgb_model, iso_model,
    shap_explainer, SHAP_AVAILABLE,
    sample_data
)

from auth import auth_bp
from routes import api_bp

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
CORS(app)

# Ensure database tables exist before serving requests
init_db()

# Global Error Handler for unexpected exceptions
@app.errorhandler(Exception)
def handle_global_error(e):
    logger.error(f"Unhandled Exception: {str(e)}", exc_info=True)
    return {
        "error": "Internal Server Error", 
        "message": "An unexpected server error occurred. Please contact an administrator."
    }, 500

app.register_blueprint(auth_bp)
app.register_blueprint(api_bp)

if __name__ == '__main__':
    logger.info("Initializing API Server...")
    logger.info(f"Loaded models: RF={bool(rf_model)}, XGB={bool(xgb_model)}, ISO={bool(iso_model)}")
    logger.info(f"Explainability: {'Enabled' if SHAP_AVAILABLE and shap_explainer else 'Disabled'}")
    
    try:
        from waitress import serve
        logger.info(f"Starting production WSGI server (Waitress) on {API_HOST}:{API_PORT}...")
        serve(app, host=API_HOST, port=API_PORT)
    except ImportError:
        logger.warning("Waitress WSGI server not installed. Falling back to Flask development server. This is NOT recommended for production.")
        app.run(host=API_HOST, port=API_PORT, debug=False)
