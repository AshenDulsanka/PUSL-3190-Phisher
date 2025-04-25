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
    service for loading and using the Gradient Boosting model for deep phishing detection
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
                
                # extract feature names - try different formats
                if isinstance(metadata, list):
                    # direct list of features
                    self.feature_list = metadata
                    logger.info(f"Loaded {len(self.feature_list)} features from list")
                elif "feature_importances" in metadata and "importance" in metadata["feature_importances"]:
                    # get ALL features from the importance dict keys, not just top ones
                    self.feature_list = list(metadata["feature_importances"]["importance"].keys())
                    logger.info(f"Extracted {len(self.feature_list)} features from importance dict")
                else:
                    # default features matching notebook's training - make sure all 30 are listed
                    logger.warning("No features found in metadata, using default feature list for deep analysis")
                    self.feature_list = [
                        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@',
                        'Redirecting//', 'PrefixSuffix-', 'SubDomains',
                        'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort',
                        'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
                        'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
                        'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust',
                        'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection',
                        'AgeofDomain', 'DNSRecording', 'WebsiteTraffic',
                        'PageRank', 'GoogleIndex', 'LinksPointingToPage',
                        'StatsReport'
                    ]
            else:
                # default features if no feature list is available
                logger.warning("Feature list file not found, using default feature list")
                self.feature_list = [
                    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@',
                    'Redirecting//', 'PrefixSuffix-', 'SubDomains',
                    'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort',
                    'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
                    'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
                    'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust',
                    'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection',
                    'AgeofDomain', 'DNSRecording', 'WebsiteTraffic',
                    'PageRank', 'GoogleIndex', 'LinksPointingToPage',
                    'StatsReport'
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
                logger.info(f"Extracting features for URL: {url[:50]}...")
                features = DeepFeatureExtractor.extract_features(url)

            # debugging - print feature keys
            logger.info(f"Features provided: {list(features.keys())}")
            logger.info(f"Feature list expected: {self.feature_list}")

            # ensure there are values for all expected features
            missing_features = set(self.feature_list) - set(features.keys())
            if missing_features:
                logger.warning(f"Missing {len(missing_features)} feature(s): {missing_features}")
                # add missing features with default values
                for feature in missing_features:
                    features[feature] = 0
                    logger.warning(f"Added missing feature with default value: {feature}=0")
            
            # prepare features for the model
            X = DeepFeatureExtractor.prepare_features_for_model(features, self.feature_list)
            logger.info(f"Prepared feature array shape: {X.shape}")
            
            # apply scaling if scaler is available
            if self.scaler is not None:
                try:
                    X = self.scaler.transform(X)
                except ValueError as e:
                    logger.error(f"Error during scaling: {e}")
                    # if there's a mismatch in features, try without scaling
                    logger.warning("Attempting to proceed without scaling")
            
            # make prediction
            prediction = self.model.predict(X)[0]
            is_phishing = prediction == 1 or prediction == 'bad'
            
            # get probability if available
            if hasattr(self.model, "predict_proba"):
                # find the index of the 'bad' class or class 1
                if hasattr(self.model, "classes_"):
                    if 'bad' in self.model.classes_:
                        bad_class_idx = list(self.model.classes_).index('bad')
                    elif 1 in self.model.classes_:
                        bad_class_idx = list(self.model.classes_).index(1)
                    else:
                        bad_class_idx = 1  # default to second class
                else:
                    bad_class_idx = 1
                
                probability = float(self.model.predict_proba(X)[0, bad_class_idx])
            else:
                probability = float(is_phishing)
            
            # calculate threat score (0-100)
            threat_score = int(round(probability * 100))
            
            # generate details based on prediction
            if is_phishing:
                if threat_score > 80:
                    details = "This URL has a very high probability of being a phishing website based on deep analysis."
                elif threat_score > 60:
                    details = "This URL appears to be a phishing website according to our comprehensive analysis."
                else:
                    details = "This URL shows some concerning characteristics of a phishing website."
            else:
                if threat_score < 20:
                    details = "Comprehensive analysis indicates this URL is legitimate with high confidence."
                elif threat_score < 40:
                    details = "This URL is likely legitimate but has some suspicious characteristics."
                else:
                    details = "This URL has multiple phishing indicators but was ultimately classified as legitimate."
            
            # add feature explanation if it's a phishing URL
            if is_phishing and threat_score > 50:
                # find the most suspicious features
                suspicious_features = []
                if features.get('UsingIP', 0) == 1:
                    suspicious_features.append("Uses an IP address instead of a domain name")
                if features.get('LongURL', 0) == 1:
                    suspicious_features.append("Uses an unusually long URL")
                if features.get('Symbol@', 0) == 1:
                    suspicious_features.append("Contains @ symbol in URL")
                if features.get('ShortURL', 0) == 1:
                    suspicious_features.append("Uses a URL shortening service")
                if features.get('AgeofDomain', 0) == 0:
                    suspicious_features.append("Domain was registered very recently")
                if features.get('IframeRedirection', 0) == 1:
                    suspicious_features.append("Page contains hidden iframes")
                if features.get('DisableRightClick', 0) == 1:
                    suspicious_features.append("Page disables right-click (anti-copying technique)")
                if features.get('UsingPopupWindow', 0) == 1:
                    suspicious_features.append("Page contains suspicious popup elements")
                if features.get('AbnormalURL', 0) == 1:
                    suspicious_features.append("URL contains suspicious keywords")
                
                if suspicious_features:
                    details += " Suspicious characteristics: " + ", ".join(suspicious_features) + "."
            
            # return prediction results with comprehensive features
            return {
                "url": url,
                "is_phishing": is_phishing,
                "threat_score": threat_score,
                "probability": probability,
                "details": details,
                "features": features,
                "features_used": self.feature_list[:10],  # show first 10 features
                "model_version": self.model_info["name"]
            }
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}", exc_info=True)
            return {
                "url": url,
                "is_phishing": False,
                "threat_score": 0,
                "probability": 0.0,
                "details": f"Error analyzing URL: {str(e)}",
                "model_version": self.model_info["name"]
            }