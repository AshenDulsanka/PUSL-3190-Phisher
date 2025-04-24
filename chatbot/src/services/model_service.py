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
    
    def _load_model(self):
        try:
            # check if model file exists
            if not os.path.exists(GRADIENT_BOOST_MODEL_PATH):
                logger.error(f"Model file not found: {GRADIENT_BOOST_MODEL_PATH}")
                return
                
            # load model
            logger.info(f"Loading model from {GRADIENT_BOOST_MODEL_PATH}")
            self.model = joblib.load(GRADIENT_BOOST_MODEL_PATH)
            
            # load scaler if available
            if os.path.exists(GRADIENT_BOOST_SCALER_PATH):
                logger.info(f"Loading scaler from {GRADIENT_BOOST_SCALER_PATH}")
                self.scaler = joblib.load(GRADIENT_BOOST_SCALER_PATH)
            
            # load feature list if available
            if os.path.exists(FEATURE_LIST_PATH):
                logger.info(f"Loading feature list from {FEATURE_LIST_PATH}")
                with open(FEATURE_LIST_PATH, 'r') as f:
                    metadata = json.load(f)
                
                # extract feature names from importance section
                if "feature_importances" in metadata and "importance" in metadata["feature_importances"]:
                    # get features from the importance dict keys
                    self.feature_list = list(metadata["feature_importances"]["importance"].keys())
                    logger.info(f"Extracted {len(self.feature_list)} features: {self.feature_list}")
                else:
                    # default extended features for deep analysis
                    logger.warning("No features found in metadata, using default feature list for deep analysis")
                    self.feature_list = [
                        # lightweight features
                        "url_length", "num_dots", "num_special_chars", 
                        "has_ip", "has_at_symbol", "num_subdomains",
                        "has_https", "has_hyphen", "is_shortened",
                        # deep analysis features
                        "domain_age", "has_iframe", "disables_right_click",
                        "has_popup", "domain_in_alexa_top_1m", "favicon_same_domain",
                        "forms_to_external", "has_login_form", "external_js_ratio"
                    ]
            else:
                # default features if no feature list is available
                self.feature_list = [
                    # lightweight features
                    "url_length", "num_dots", "num_special_chars", 
                    "has_ip", "has_at_symbol", "num_subdomains",
                    "has_https", "has_hyphen", "is_shortened",
                    # deep analysis features
                    "domain_age", "has_iframe", "disables_right_click",
                    "has_popup", "domain_in_alexa_top_1m", "favicon_same_domain"
                ]
            
            logger.info("Model and related artifacts loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}", exc_info=True)