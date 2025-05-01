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
CHATBOT_MODEL_PATH = MODELS_DIR / "chatbot" / "chatbot_model.pkl"
CHATBOT_SCALER_PATH = MODELS_DIR / "chatbot" / "chatbot_scaler.pkl"
CHATBOT_METADATA_PATH = MODELS_DIR / "chatbot" / "chatbot_metadata.json"
CHATBOT_FEATURES_PATH = MODELS_DIR / "chatbot" / "chatbot_features.json"

# API configuration
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

# Redis configuration for analysis caching and continuous learning
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_DB = int(os.getenv("REDIS_DB"))
REDIS_ENABLED = os.getenv("REDIS_ENABLED").lower() in ("true", "1", "t")

# security settings
API_KEY_HEADER = "X-API-Key"
API_KEY = os.getenv("API_KEY_CB")

# HTTP settings
HTTP_WHITELIST = ["example.com", "info.cern.ch", "localhost"]

# analysis settings
TYPOSQUATTING_DISTANCE_THRESHOLD = float(os.getenv("TYPOSQUATTING_DISTANCE_THRESHOLD"))
ANALYSIS_TIMEOUT = int(os.getenv("ANALYSIS_TIMEOUT"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE_CB"))

# model threshold settings
PHISHING_THRESHOLD_CB = float(os.getenv("PHISHING_THRESHOLD_CB"))
WARNING_THRESHOLD_CB = float(os.getenv("WARNING_THRESHOLD_CB"))

# chatbot specific settings
CHATBOT_SESSION_EXPIRE_MINUTES = int(os.getenv("CHATBOT_SESSION_EXPIRE_MINUTES"))