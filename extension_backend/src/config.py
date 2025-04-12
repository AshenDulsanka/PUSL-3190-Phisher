import os
from pathlib import Path

# base paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs" / "extension_backend"

# ensure log directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# model paths
RANDOM_FOREST_MODEL_PATH = MODELS_DIR / "random_forest_model" / "random_forest_model.pkl"
RANDOM_FOREST_SCALER_PATH = MODELS_DIR / "random_forest_model" / "random_forest_scaler.pkl"
FEATURE_LIST_PATH = MODELS_DIR / "random_forest_model" / "random_forest_metadata.json"

# API settings
API_PREFIX = "/api"
API_DEBUG = os.getenv("API_DEBUG", "False").lower() in ("true", "1", "t")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# CORS settings
CORS_ORIGINS = [
    "chrome-extension://*/",  # allow Chrome extensions
    "http://localhost:3000",  # local frontend development
    "http://localhost:8000",  # local testing
]

# security settings
API_KEY_HEADER = "X-API-Key"
API_KEY = os.getenv("API_KEY", "phisher-dev-key")

# rate limiting
RATE_LIMIT_PER_MINUTE = 60