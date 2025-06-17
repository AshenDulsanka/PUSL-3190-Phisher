import joblib
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Tuple
import os

from ..config import BROWSER_EXTENSION_MODEL_PATH, BROWSER_EXTENSION_SCALER_PATH, FEATURE_LIST_PATH
from ..logging_config import get_logger
from ..utils.feature_extraction import FeatureExtractor
from .database_integration_service import DatabaseIntegrationService

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
            "name": "browser_extension_random_forest",
            "type": "random_forest",
            "version": "1.0"
        }
        
        # load the model and related artifacts
        self._load_model()
    
    def _load_model(self):
        try:
            # check if model file exists
            if not os.path.exists(BROWSER_EXTENSION_MODEL_PATH):
                logger.error(f"Model file not found: {BROWSER_EXTENSION_MODEL_PATH}")
                return
                
            # load model
            logger.info(f"Loading model from {BROWSER_EXTENSION_MODEL_PATH}")
            self.model = joblib.load(BROWSER_EXTENSION_MODEL_PATH)
            
            # load scaler if available
            if os.path.exists(BROWSER_EXTENSION_SCALER_PATH):
                logger.info(f"Loading scaler from {BROWSER_EXTENSION_SCALER_PATH}")
                self.scaler = joblib.load(BROWSER_EXTENSION_SCALER_PATH)
            
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
                    # default lightweight features if no feature list is found in metadata
                    logger.warning("No features found in metadata, using default feature list")
                    self.feature_list = [
                        "url_length", "num_dots", "num_special_chars", 
                        "has_ip", "has_at_symbol", "num_subdomains", 
                        "has_https", "has_hyphen", "is_shortened"
                    ]
            else:
                # default lightweight features if no feature list is available
                self.feature_list = [
                    "url_length", "num_dots", "num_special_chars", 
                    "has_ip", "has_at_symbol", "num_subdomains", 
                    "has_https", "has_hyphen", "is_shortened"
                ]
            
            logger.info("Model and related artifacts loaded successfully")
            self._register_lightweight_model_in_database()
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}", exc_info=True)

    def _register_lightweight_model_in_database(self):
        """register or update the model in the database"""
        try:
            if not hasattr(self, 'db_integration'):
                self.db_integration = DatabaseIntegrationService()
                
            # create model metadata if we have a model loaded
            if self.model is not None:
                model_data = {
                    "name": self.model_info["name"],
                    "type": self.model_info["type"],
                    "version": self.model_info["version"],
                    "parameters": json.dumps({
                        "feature_count": len(self.feature_list) if self.feature_list else 0,
                        "has_scaler": self.scaler is not None
                    })
                }
                
                # try to register
                self.db_integration.register_lightweight_model(model_data)
                logger.info(f"Registered lightweight model {self.model_info['name']} in database")
        except Exception as e:
            logger.error(f"Error registering lightweight model in database: {str(e)}")
    
    def predict(self, url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            # Extract features if not provided
            if features is None:
                features = FeatureExtractor.extract_features(url)

            # Prepare features for the model
            if self.feature_list:
                X = FeatureExtractor.prepare_features_for_model(features, self.feature_list)
            else:
                X = np.array(list(features.values())).reshape(1, -1)
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Get prediction
            raw_prediction = self.model.predict(X_scaled)[0]
            raw_probability = float(self.model.predict_proba(X_scaled)[0, 1])
            
            # Multi-threshold approach for better accuracy
            high_confidence_threshold = 0.7    # Definitely phishing
            medium_confidence_threshold = 0.4  # Suspicious
            low_confidence_threshold = 0.2     # Probably legitimate
            
            # Determine classification
            if raw_probability >= high_confidence_threshold:
                is_phishing = True
                confidence = "High"
                threat_score = int(85 + (raw_probability - high_confidence_threshold) * 50)
            elif raw_probability >= medium_confidence_threshold:
                is_phishing = True  # Err on the side of caution
                confidence = "Medium"
                threat_score = int(40 + (raw_probability - medium_confidence_threshold) * 45)
            elif raw_probability >= low_confidence_threshold:
                is_phishing = False
                confidence = "Medium"
                threat_score = int(20 + (raw_probability - low_confidence_threshold) * 20)
            else:
                is_phishing = False
                confidence = "High"
                threat_score = int(raw_probability * 100)
            
            # Additional heuristic checks for edge cases
            if not is_phishing:
                # Check for obvious phishing indicators
                if (features.get('has_ip', 0) == 1 or 
                    features.get('suspicious_keywords', 0) >= 3 or
                    features.get('brand_keywords', 0) >= 2):
                    is_phishing = True
                    threat_score = max(threat_score, 60)
                    confidence = "High"
            
            # Generate detailed explanation
            details = self._generate_detailed_explanation(
                is_phishing, threat_score, raw_probability, features
            )
            
            return {
                "url": url,
                "is_phishing": is_phishing,
                "threat_score": min(threat_score, 100),
                "probability": raw_probability,
                "confidence": confidence,
                "details": details,
                "model_version": self.model_info["version"]
            }
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}", exc_info=True)
            return {
                "url": url,
                "is_phishing": False,
                "threat_score": 0,
                "probability": 0.0,
                "confidence": "Low",
                "details": "Error analyzing URL. Please verify manually.",
                "model_version": self.model_info["version"]
            }
    
    def _generate_detailed_explanation(self, is_phishing, threat_score, probability, features):
        explanations = []
        
        if features.get('has_ip', 0):
            explanations.append("Uses IP address instead of domain name")
        
        if features.get('suspicious_tld', 0):
            explanations.append("Uses suspicious top-level domain")
        
        if features.get('brand_keywords', 0) >= 2:
            explanations.append("Contains multiple brand keywords (potential impersonation)")
        
        if features.get('homograph_attack', 0) > 0:
            explanations.append("Contains characters that mimic legitimate domains")
        
        if features.get('domain_entropy', 0) > 4:
            explanations.append("Domain name has high randomness")
        
        if features.get('suspicious_keywords', 0) >= 2:
            explanations.append("Contains multiple suspicious keywords")
        
        if features.get('url_shortener', 0):
            explanations.append("Uses URL shortening service")
        
        if not explanations:
            if is_phishing:
                explanations.append("Multiple subtle indicators suggest this may be malicious")
            else:
                explanations.append("No significant suspicious indicators detected")
        
        return "; ".join(explanations)