import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# base paths
# base paths - adjust for docker environment
if os.path.exists('/app'):
    # docker
    BASE_DIR = Path('/app')
else:
    # local development
    BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs" / "extension_backend"

# ensure log directory exists and is writable
os.makedirs(LOGS_DIR, exist_ok=True)
try:
    # Test write access by touching a file
    test_file = LOGS_DIR / ".write_test"
    with open(test_file, 'w') as f:
        f.write("test")
    os.remove(test_file)
except Exception as e:
    print(f"WARNING: Cannot write to logs directory: {e}")

# model paths
RANDOM_FOREST_MODEL_PATH = MODELS_DIR / "random_forest_model" / "random_forest_model.pkl"
RANDOM_FOREST_SCALER_PATH = MODELS_DIR / "random_forest_model" / "random_forest_scaler.pkl"
FEATURE_LIST_PATH = MODELS_DIR / "random_forest_model" / "random_forest_metadata.json"

# API settings
API_PREFIX = "/api"
API_DEBUG = os.getenv("API_DEBUG_BE").lower() in ("true", "1", "t")
API_HOST = os.getenv("API_HOST_BE")
API_PORT = int(os.getenv("API_PORT_BE"))

# CORS settings
CORS_ORIGINS = [
    "chrome-extension://*/",  # allow Chrome extensions
    "http://localhost:3000",  # local frontend development
    "http://localhost:8000",  # local testing
]

# security settings
API_KEY_HEADER = "X-API-Key"
API_KEY = os.getenv("API_KEY_BE", "phisher-dev-key")

# rate limiting
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))