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
            "version": "4.0"
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
                
                # Try to extract the 33 features from ultra-high recall metadata
                if "features" in metadata and "feature_list" in metadata["features"]:
                    self.feature_list = metadata["features"]["feature_list"]
                    logger.info(f"Loaded {len(self.feature_list)} features from ultra-high recall model")
                elif "feature_list" in metadata:
                    self.feature_list = metadata["feature_list"]
                    logger.info(f"Loaded {len(self.feature_list)} features from metadata")
                else:
                    logger.warning("No features found in metadata, using ultra-high recall default")
                    self.feature_list = [
                        'has_ip', 'has_https', 'suspicious_tld', 'domain_length',
                        'subdomain_count', 'excessive_subdomains', 'ultra_excessive_subdomains',
                        'has_hyphen_in_domain', 'multiple_hyphens', 'high_digit_ratio', 'high_domain_entropy',
                        'url_length', 'extremely_long_url', 'suspicious_url_length', 'deep_path', 'long_query',
                        'path_length', 'query_length', 'keyword_count', 'has_phishing_keywords',
                        'multiple_phishing_keywords', 'has_brand_impersonation', 'has_suspicious_domain_pattern',
                        'is_shortener', 'has_at_symbol', 'has_double_slash', 'special_char_density',
                        'high_special_char_density', 'homograph_risk', 'potential_typosquatting',
                        'risk_factor_count', 'multiple_critical_risks', 'ultra_high_risk'
                    ]
            else:
                # Ultra-high recall default features (33 features)
                logger.warning("Feature list file not found, using ultra-high recall default")
                self.feature_list = [
                    'has_ip', 'has_https', 'suspicious_tld', 'domain_length',
                    'subdomain_count', 'excessive_subdomains', 'ultra_excessive_subdomains',
                    'has_hyphen_in_domain', 'multiple_hyphens', 'high_digit_ratio', 'high_domain_entropy',
                    'url_length', 'extremely_long_url', 'suspicious_url_length', 'deep_path', 'long_query',
                    'path_length', 'query_length', 'keyword_count', 'has_phishing_keywords',
                    'multiple_phishing_keywords', 'has_brand_impersonation', 'has_suspicious_domain_pattern',
                    'is_shortener', 'has_at_symbol', 'has_double_slash', 'special_char_density',
                    'high_special_char_density', 'homograph_risk', 'potential_typosquatting',
                    'risk_factor_count', 'multiple_critical_risks', 'ultra_high_risk'
                ]
            
            logger.info(f"Final feature list: {len(self.feature_list)} features")
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
                        "has_scaler": self.scaler is not None,
                        "optimization": "ultra_high_recall"
                    })
                }
                
                # try to register
                self.db_integration.register_lightweight_model(model_data)
                logger.info(f"Registered ultra-high recall model {self.model_info['name']} in database")
        except Exception as e:
            logger.error(f"Error registering model in database: {str(e)}")
    
    def predict(self, url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            # check if model is loaded
            if self.model is None:
                logger.error("Model not loaded")
                return {
                    "url": url,
                    "is_phishing": False,
                    "threat_score": 0,
                    "probability": 0.0,
                    "details": "Unable to make prediction: Model not loaded",
                    "model_version": self.model_info["version"],
                    "features_used": []
                }
            
            # extract features if not provided
            if features is None:
                features = FeatureExtractor.extract_features(url)

            logger.info(f"Features extracted: {len(features)} features for URL: {url[:50]}...")
            
            # prepare features for the model using the correct feature list
            if self.feature_list:
                X = FeatureExtractor.prepare_features_for_model(features, self.feature_list)
                logger.info(f"Prepared feature array shape: {X.shape} for {len(self.feature_list)} features")
            else:
                X = np.array(list(features.values())).reshape(1, -1)
                logger.warning(f"No feature list available, using all {X.shape[1]} features")
            
            # scale features
            X_scaled = self.scaler.transform(X)
            
            # get prediction
            raw_prediction = self.model.predict(X_scaled)[0]
            raw_probability = float(self.model.predict_proba(X_scaled)[0, 1])
            
            logger.info(f"Raw model output: prediction={raw_prediction}, probability={raw_probability:.4f}")
            
            PHISHING_THRESHOLD = 0.4  # Lower threshold for maximum security
            
            # Apply the threshold
            is_phishing = raw_probability >= PHISHING_THRESHOLD
            
            # Calculate threat score
            threat_score = int(raw_probability * 100)
            
            # Ultra-sensitive override - never miss critical indicators
            if not is_phishing:
                if (features.get('has_ip', 0) == 1 or 
                    features.get('ultra_high_risk', 0) == 1 or
                    features.get('multiple_critical_risks', 0) == 1):
                    is_phishing = True
                    threat_score = max(threat_score, 80)
                    logger.info("Ultra-sensitive override: Critical phishing indicators detected")
            
            logger.info(f"Final decision: is_phishing={is_phishing}, threat_score={threat_score}")
            
            # Generate simple details
            if is_phishing:
                if threat_score > 85:
                    details = "HIGH RISK: This URL has a very high probability of being a phishing website."
                elif threat_score > 60:
                    details = "PHISHING DETECTED: This URL appears to be a phishing website."
                else:
                    details = "SUSPICIOUS: This URL shows characteristics of a phishing website."
            else:
                if threat_score > 30:
                    details = "CAUTION: This URL has some suspicious characteristics but appears legitimate."
                else:
                    details = "SAFE: This URL appears to be legitimate."
            
            # track the model evaluation in the database if available
            if hasattr(self, 'db_integration'):
                self.db_integration.track_lightweight_model_evaluation({
                    "model_name": self.model_info["name"],
                    "url": url,
                    "is_phishing": is_phishing,
                    "score": threat_score / 100.0
                })
            
            # Return the result
            return {
                "url": url,
                "is_phishing": is_phishing,
                "threat_score": threat_score,
                "probability": raw_probability,
                "details": details,
                "model_version": self.model_info["version"],
                "features_used": self.feature_list  
            }
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}", exc_info=True)
            return {
                "url": url,
                "is_phishing": False,
                "threat_score": 0,
                "probability": 0.0,
                "details": "Error analyzing URL. Please verify manually.",
                "model_version": self.model_info["version"],
                "features_used": self.feature_list or []
            }