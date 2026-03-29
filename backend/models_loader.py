import os
import json
import numpy as np
import pandas as pd
import joblib

from config import MODELS_FOLDER, DATA_FOLDER, logger


"""
Model loader.
Initializes ML models, preprocessors, and datasets; failures fall back to None
so the API can continue to serve partial functionality.
"""
# Optional SHAP integration for explainability
SHAP_AVAILABLE = False
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    pass


try:
    rf_model = joblib.load(os.path.join(MODELS_FOLDER, 'model_rf_v1.joblib'))
except Exception as e:
    logger.error(f"Failed to load RF model: {e}")
    rf_model = None

try:
    xgb_model = joblib.load(os.path.join(MODELS_FOLDER, 'model_xgb_v1.joblib'))
except Exception as e:
    logger.error(f"Failed to load XGBoost model: {e}")
    xgb_model = None

try:
    iso_model = joblib.load(os.path.join(MODELS_FOLDER, 'model_iso_v1.joblib'))
except Exception as e:
    logger.error(f"Failed to load Isolation Forest model: {e}")
    iso_model = None

try:
    scaler = joblib.load(os.path.join(MODELS_FOLDER, 'scaler_v1.joblib'))
except Exception as e:
    logger.error(f"Failed to load scaler: {e}")
    scaler = None

try:
    with open(os.path.join(MODELS_FOLDER, 'label_mapping_v1.json'), 'r') as f:
        label_mapping = json.load(f)
    # Ensure keys are integers
    label_mapping = {int(k): v for k, v in label_mapping.items()}
except Exception as e:
    label_mapping = {}

try:
    with open(os.path.join(MODELS_FOLDER, 'feature_list_v1.json'), 'r') as f:
        feature_list = json.load(f).get('features', [])
except Exception as e:
    feature_list = []
shap_explainer = None
if SHAP_AVAILABLE and xgb_model is not None:
    try:
        # Load a small background sample to initialize the tree explainer
        X_train = np.load(os.path.join(MODELS_FOLDER, 'X_train.npy'))
        shap_explainer = shap.TreeExplainer(xgb_model, X_train[:100])
        del X_train
    except Exception as e:
        pass
csv_files = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
]

# Load samples separated by attack type for balanced sampling
sample_data = None
samples_by_attack = {}  # Dictionary to hold samples grouped by attack type
try:
    all_samples = []
    for csv_file in csv_files:
        file_path = os.path.join(DATA_FOLDER, csv_file)
        if os.path.exists(file_path):
            # Load samples from each file
            df = pd.read_csv(file_path, nrows=2000)
            df.columns = df.columns.str.strip()
            all_samples.append(df)
    
    if all_samples:
        sample_data = pd.concat(all_samples, ignore_index=True)
        
        # Group samples by attack type (Label column)
        if 'Label' in sample_data.columns:
            for label in sample_data['Label'].unique():
                label_samples = sample_data[sample_data['Label'] == label]
                samples_by_attack[label] = label_samples.reset_index(drop=True)
            logger.info(f"Loaded {len(sample_data)} samples across {len(samples_by_attack)} attack types")
        else:
            logger.info(f"Loaded {len(sample_data)} samples (Label column not found)")
except Exception as e:
    logger.error(f"Failed to load data: {e}")
