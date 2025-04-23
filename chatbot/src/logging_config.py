import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path

from .config import LOGS_DIR

# create a formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# create log filename with date
log_filename = f"chatbot_{datetime.now().strftime('%Y-%m-%d')}.log"
log_filepath = LOGS_DIR / log_filename

# create handlers
file_handler = logging.handlers.RotatingFileHandler(
    log_filepath, maxBytes=10485760, backupCount=5
)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

# configure root logger
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# function to get a logger for a specific module
def get_logger(name):
    logger = logging.getLogger(name)
    return logger