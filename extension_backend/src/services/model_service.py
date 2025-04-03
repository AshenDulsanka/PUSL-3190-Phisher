import joblib
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Tuple
import os

from ..config import RANDOM_FOREST_MODEL_PATH, RANDOM_FOREST_SCALER_PATH, FEATURE_LIST_PATH
from ..logging_config import get_logger
from ..utils.feature_extraction import FeatureExtractor

logger = get_logger(__name__)

class ModelService:
    """
    service for loading and using ML models for phishing detection
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
            "name": "random_forest_v1",
            "type": "random_forest",
            "version": "1.0"
        }
        
        # load the model and related artifacts
        self._load_model()
    
    def _load_model(self):
        try:
            # check if model file exists
            if not os.path.exists(RANDOM_FOREST_MODEL_PATH):
                logger.error(f"Model file not found: {RANDOM_FOREST_MODEL_PATH}")
                return
                
            # load model
            logger.info(f"Loading model from {RANDOM_FOREST_MODEL_PATH}")
            self.model = joblib.load(RANDOM_FOREST_MODEL_PATH)
            
            # load scaler if available
            if os.path.exists(RANDOM_FOREST_SCALER_PATH):
                logger.info(f"Loading scaler from {RANDOM_FOREST_SCALER_PATH}")
                self.scaler = joblib.load(RANDOM_FOREST_SCALER_PATH)
            
            # load feature list if available
            if os.path.exists(FEATURE_LIST_PATH):
                logger.info(f"Loading feature list from {FEATURE_LIST_PATH}")
                with open(FEATURE_LIST_PATH, 'r') as f:
                    self.feature_list = json.load(f)
            else:
                # default lightweight features if no feature list is available
                self.feature_list = [
                    "url_length", "num_dots", "num_special_chars", 
                    "has_ip", "has_at_symbol", "num_subdomains", 
                    "has_https", "has_hyphen", "is_shortened"
                ]
            
            logger.info("Model and related artifacts loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}", exc_info=True)
    
    def predict(self, url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            # check if model is loaded
            if self.model is None:
                logger.error("Model not loaded")
                return {
                    "is_phishing": False,
                    "threat_score": 0,
                    "probability": 0.0,
                    "details": "Unable to make prediction: Model not loaded",
                    "model_version": self.model_info["version"]
                }
            
            # extract features if not provided
            if features is None:
                features = FeatureExtractor.extract_features(url)
            
            # prepare features for the model
            if self.feature_list:
                # use feature list to ensure correct order
                X = FeatureExtractor.prepare_features_for_model(features, self.feature_list)
            else:
                # fallback if feature list is not available
                X = np.array(list(features.values())).reshape(1, -1)
            
            # apply scaling if scaler is available
            if self.scaler is not None:
                X = self.scaler.transform(X)
            
            # make prediction
            prediction = self.model.predict(X)[0]
            is_phishing = prediction == 'bad'
            
            # get probability if available
            if hasattr(self.model, "predict_proba"):
                # find the index of the 'bad' class
                bad_class_idx = list(self.model.classes_).index('bad') if 'bad' in self.model.classes_ else 1
                probability = float(self.model.predict_proba(X)[0, bad_class_idx])
            else:
                probability = float(is_phishing)
            
            # calculate threat score (0-100)
            threat_score = int(round(probability * 100))
            
            # generate details based on prediction
            if is_phishing:
                if threat_score > 80:
                    details = "This URL has a very high probability of being a phishing website."
                elif threat_score > 60:
                    details = "This URL appears to be a phishing website."
                else:
                    details = "This URL shows some characteristics of a phishing website."
            else:
                if threat_score < 20:
                    details = "This URL appears to be legitimate with high confidence."
                elif threat_score < 40:
                    details = "This URL is likely legitimate but has some suspicious characteristics."
                else:
                    details = "This URL has some phishing indicators but was classified as legitimate."
            
            # add feature explanation if it's a phishing URL
            if is_phishing and threat_score > 50:
                # find the most suspicious features
                suspicious_features = []
                if features.get('has_ip', 0) == 1:
                    suspicious_features.append("Uses an IP address instead of a domain name")
                if features.get('url_length', 0) > 75:
                    suspicious_features.append("Uses an unusually long URL")
                if features.get('has_at_symbol', 0) == 1:
                    suspicious_features.append("Contains @ symbol in URL")
                if features.get('is_shortened', 0) == 1:
                    suspicious_features.append("Uses a URL shortening service")
                
                if suspicious_features:
                    details += " Suspicious characteristics: " + ", ".join(suspicious_features) + "."
            
            # return prediction results
            return {
                "is_phishing": is_phishing,
                "threat_score": threat_score,
                "probability": probability,
                "details": details,
                "features_used": self.feature_list[:5] if self.feature_list else None,  # Show first 5 features
                "model_version": self.model_info["version"]
            }
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}", exc_info=True)
            return {
                "is_phishing": False,
                "threat_score": 0,
                "probability": 0.0,
                "details": f"Error analyzing URL: {str(e)}",
                "model_version": self.model_info["version"]
            }