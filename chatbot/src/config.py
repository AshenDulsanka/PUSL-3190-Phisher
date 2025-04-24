import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# base paths - adjust for docker environment
if os.path.exists('/app'):
    # docker environment
    BASE_DIR = Path('/app')
else:
    # local development
    BASE_DIR = Path(__file__).resolve().parent.parent

MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs" / "chatbot"

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
GRADIENT_BOOST_MODEL_PATH = MODELS_DIR / "gradient_boosting_model" / "gradient_boost_model.pkl"
GRADIENT_BOOST_SCALER_PATH = MODELS_DIR / "gradient_boosting_model" / "gradient_boost_scaler.pkl"
FEATURE_LIST_PATH = MODELS_DIR / "gradient_boosting_model" / "gradient_boost_metadata.json"

# API settings
API_PREFIX = os.getenv("API_PREFIX_CB")
API_DEBUG = os.getenv("API_DEBUG_CB").lower() in ("true", "1", "t")
API_HOST = os.getenv("API_HOST_CB")
API_PORT = int(os.getenv("API_PORT_CB"))

# CORS settings
CORS_ORIGINS = [
    os.getenv("WEB_CLIENT_URL"),  # frontend 
    os.getenv("WEB_SERVER_URL"),  # server
    os.getenv("WEB_CLIENT_DOCKER_URL"), # docker container
    os.getenv("WEB_SERVER_DOCKER_URL"), # docker container
]

# security settings
API_KEY_HEADER = "X-API-Key"
API_KEY = os.getenv("API_KEY_CB")

# rate limiting
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE_CB"))