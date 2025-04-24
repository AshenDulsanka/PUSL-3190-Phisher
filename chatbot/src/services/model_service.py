import joblib
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Tuple
import os

from ..config import GRADIENT_BOOST_MODEL_PATH, GRADIENT_BOOST_SCALER_PATH, FEATURE_LIST_PATH
from ..logging_config import get_logger
from ..utils.feature_extraction import DeepFeatureExtractor

logger = get_logger(__name__)

class ModelService:
    """
    service for loading and using the gradient boosting model for deep phishing detection
    implemented as a singleton to avoid loading the model multiple times
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.model = None
        self.scaler = None
        self.feature_list = []
        self.model_info = {
            "name": "gradient_boost_model",
            "type": "gradient_boost",
            "version": "1.0"
        }
        
        # load the model and related artifacts
        self._load_model()
    
