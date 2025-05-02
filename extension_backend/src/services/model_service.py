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
            "name": "random_forest_v1",
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

            # debugging - print feature keys
            logger.info(f"Features provided: {list(features.keys())}")
            logger.info(f"Feature list expected: {self.feature_list}")

            # filter features to only include those in the feature_list
            filtered_features = {}
            for feature in self.feature_list:
                if feature in features:
                    filtered_features[feature] = features[feature]
                else:
                    filtered_features[feature] = 0  # default value
                    logger.warning(f"Missing feature: {feature}")
            
            # prepare features for the model
            if self.feature_list:
                # use feature list to ensure correct order
                X = FeatureExtractor.prepare_features_for_model(features, self.feature_list)
                logger.info(f"Prepared feature array shape: {X.shape}")
            else:
                # fallback if feature list is not available
                X = np.array(list(features.values())).reshape(1, -1)
            
            # After scaling the features and before making prediction, add debug logging:
            logger.info(f"Making prediction for URL: {url[:50]}...")
            
            # Get the raw prediction and probability
            X_scaled = self.scaler.transform(X)
            raw_prediction = self.model.predict(X_scaled)[0]
            
            # Get the probability of the positive class (phishing)
            # Ensure we're getting probability for class 1 (phishing)
            raw_probability = float(self.model.predict_proba(X_scaled)[0, 1])
            logger.info(f"URL features for {url[:30]}: {features}")
            
            logger.info(f"Raw model output: prediction={raw_prediction}, probability={raw_probability:.4f}")
            
            # Use a conservative threshold - URLs are considered phishing ONLY if 
            # probability is high enough
            PHISHING_THRESHOLD = 0.8 
            
            # Apply the threshold to determine if it's phishing
            is_phishing = raw_probability >= PHISHING_THRESHOLD
            
            # Calculate threat score based on raw probability
            threat_score = int(raw_probability * 100)
            
            logger.info(f"Final decision: is_phishing={is_phishing}, threat_score={threat_score}, threshold={PHISHING_THRESHOLD}")
            
            # Add more context to the result
            details = ""
            if is_phishing:
                if threat_score > 85:
                    details = "This URL has a very high probability of being a phishing website."
                elif threat_score > 70:
                    details = "This URL appears to be a phishing website."
                else:
                    details = "This URL shows some characteristics of a phishing website."
            else:
                if threat_score > 50:
                    details = "This URL has some suspicious characteristics but appears to be legitimate."
                else:
                    details = "This URL appears to be legitimate."
            
            # Return the result
            return {
                "url": url,
                "is_phishing": is_phishing,
                "threat_score": threat_score,
                "probability": raw_probability,
                "details": details
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