import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

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
    # test write access by touching a file
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
API_PREFIX = os.getenv("API_PREFIX_BE")
API_DEBUG = os.getenv("API_DEBUG_BE").lower() in ("true", "1", "t")
API_HOST = os.getenv("API_HOST_BE")
API_PORT = int(os.getenv("API_PORT_BE"))

# CORS settings
CORS_ORIGINS = [
    os.getenv("CHROME_EXTENSION"),  # allow Chrome extensions
    os.getenv("WEB_CLIENT_URL"),  # frontend 
    os.getenv("EXTENSION_BACKEND_URL"),  # testing
]

# security settings
API_KEY_HEADER = "X-API-Key"
API_KEY = os.getenv("API_KEY_BE")

# rate limiting
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE_BE"))