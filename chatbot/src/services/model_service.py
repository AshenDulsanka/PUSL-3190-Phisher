import joblib
import json
import numpy as np
import os
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

from ..config import CHATBOT_MODEL_PATH, CHATBOT_SCALER_PATH, CHATBOT_FEATURES_PATH, CHATBOT_METADATA_PATH, PHISHING_THRESHOLD_CB, WARNING_THRESHOLD_CB
from ..logging_config import get_logger
from ..utils.feature_extraction import FeatureExtractor
from ..models.schemas import ChatbotURLResponse, DeepAnalysisResult
from .redis_service import RedisService
from .database_integration_service import DatabaseIntegrationService

logger = get_logger(__name__)

class ModelService:
    """
    service for loading and using the deep analysis ML model for the chatbot
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
            "name": "advanced_random_forest_model",
            "type": "random_forest",
            "version": "3.0"
        }
        self.redis = RedisService()

        # load the model and related artifacts
        self._load_model()
    
    def _load_model(self):
        try:
            # check if model file exists
            if not os.path.exists(CHATBOT_MODEL_PATH):
                logger.error(f"Model file not found: {CHATBOT_MODEL_PATH}")
                return
            
            # load model
            logger.info(f"Loading chatbot model from {CHATBOT_MODEL_PATH}")
            self.model = joblib.load(CHATBOT_MODEL_PATH)
            
            # load scaler if available
            if os.path.exists(CHATBOT_SCALER_PATH):
                logger.info(f"Loading scaler from {CHATBOT_SCALER_PATH}")
                self.scaler = joblib.load(CHATBOT_SCALER_PATH)
            else:
                logger.warning(f"Scaler not found at {CHATBOT_SCALER_PATH}")
            
            # load feature list
            if os.path.exists(CHATBOT_FEATURES_PATH):
                logger.info(f"Loading feature list from {CHATBOT_FEATURES_PATH}")
                with open(CHATBOT_FEATURES_PATH, 'r') as f:
                    feature_config = json.load(f)
                    if "selected_features" in feature_config:
                        self.feature_list = feature_config["selected_features"]
                    else:
                        self.feature_list = feature_config  # fallback for old format
                    logger.info(f"Loaded {len(self.feature_list)} features")
            else:
                logger.warning(f"Feature list not found at {CHATBOT_FEATURES_PATH}")
                # updated feature list
                self.feature_list = [
                    # top high-impact features from analysis
                    'uses_http', 'LegitimacyScore', 'PrefixSuffix-', 
                    'WebsiteTraffic', 'DNSRecording', 'PageRank', 
                    'GoogleIndex', 'SubDomains', 'DomainLength', 
                    'LinksPointingToPage', 'StatsReport', 'DomainRegLen', 
                    'RequestURL', 'AbnormalURL', 'Symbol@', 'IsTyposquatting',
                    'BrandInSubdomain', 'UsingIP', 'AgeofDomain',
                    # enhanced ultra-high recall features
                    'has_ip', 'has_https', 'suspicious_tld', 'domain_length',
                    'subdomain_count', 'excessive_subdomains', 'ultra_excessive_subdomains',
                    'has_hyphen_in_domain', 'multiple_hyphens', 'high_digit_ratio',
                    'url_length', 'extremely_long_url', 'suspicious_url_length',
                    'keyword_count', 'has_phishing_keywords', 'multiple_phishing_keywords',
                    'has_brand_impersonation', 'has_suspicious_domain_pattern'
                ]
            
            # load model metadata if available
            if os.path.exists(CHATBOT_METADATA_PATH):
                logger.info(f"Loading model metadata from {CHATBOT_METADATA_PATH}")
                with open(CHATBOT_METADATA_PATH, 'r') as f:
                    metadata = json.load(f)
                    if "model_info" in metadata:
                        self.model_info.update(metadata["model_info"])
                    else:
                        # fallback for direct metadata fields
                        if "name" in metadata:
                            self.model_info["name"] = metadata["name"]
                        if "type" in metadata:
                            self.model_info["type"] = metadata["type"]
                        if "version" in metadata:
                            self.model_info["version"] = metadata["version"]
            
            logger.info("Chatbot model and related artifacts loaded successfully")
            logger.info(f"Model: {self.model_info}")
            logger.info(f"Features: {len(self.feature_list)}")
            self._register_model_in_database()
            
        except Exception as e:
            logger.error(f"Error loading chatbot model: {str(e)}", exc_info=True)

    def _register_model_in_database(self):
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
                        "optimization": "ultra_comprehensive",
                        "purpose": "chatbot_phishing_detection"
                    })
                }
                
                # try to register
                self.db_integration.register_model(model_data)
                logger.info(f"Registered model {self.model_info['name']} in database")
        except Exception as e:
            logger.error(f"Error registering model in database: {str(e)}")
    
    def _get_deep_analysis(self, url: str, features: Dict[str, Any], raw_probability: float) -> DeepAnalysisResult:
        try:
            domain, full_domain = FeatureExtractor.get_domain(url)
            
            # get domain information
            whois_info = None
            if domain:
                whois_info = FeatureExtractor.get_domain_info(domain)
            
            # build the DeepAnalysisResult object
            deep_analysis = DeepAnalysisResult(
                domain_age_days=whois_info['domain_age'] if whois_info else None,
                registration_details={
                    'registration_length_days': whois_info['registration_length'] if whois_info else None,
                },
                dns_records={
                    'has_mx': features.get('PageRank', 0) == 1,
                    'has_spf': False,  # would need additional extraction
                    'has_dmarc': False,  # would need additional extraction
                    'total_records': features.get('WebsiteTraffic', 0)
                },
                security_signals={
                    'uses_https': features.get('uses_http', 1) == 0,
                    'valid_certificate': features.get('uses_http', 1) == 0,  # simplified assumption
                    'suspicious_redirects': False  # would need additional extraction
                },
                content_analysis={
                    'form_count': 0,  # would need extraction from HTML content
                    'external_links': features.get('LinksPointingToPage', 0),
                    'iframe_count': 0  # would need extraction from HTML content
                },
                typosquatting_info={
                    'is_typosquatting': features.get('IsTyposquatting', 0) == 1
                },
                brand_impersonation={
                    'detected': features.get('BrandInSubdomain', 0) == 1
                }
            )
            
            return deep_analysis
        except Exception as e:
            logger.error(f"Error generating deep analysis: {str(e)}", exc_info=True)
            return DeepAnalysisResult()
    
    def _get_recommendations(self, is_phishing: bool, threat_score: int, features: Dict[str, Any]) -> List[str]:
        recommendations = []
        
        if is_phishing:
            recommendations.append("This website appears to be a phishing attempt. Do not provide any personal information.")
            if features.get('IsTyposquatting', 0) == 1:
                recommendations.append("The domain appears to be impersonating a legitimate website through typosquatting.")
            if features.get('BrandInSubdomain', 0) == 1:
                recommendations.append("The website may be attempting to impersonate a brand using subdomains.")
            if features.get('uses_http', 1) == 1:
                recommendations.append("The website doesn't use secure HTTPS protocol, which is unusual for legitimate sites collecting information.")
            if features.get('ultra_high_risk', 0) == 1:
                recommendations.append("Multiple critical risk factors detected - this is extremely dangerous.")
        elif threat_score >= 30:  # suspicious but not phishing
            recommendations.append("This website shows some suspicious patterns. Exercise caution when sharing information.")
            if features.get('uses_http', 1) == 1:
                recommendations.append("The website doesn't use secure HTTPS protocol, which increases risk.")
            recommendations.append("Verify the domain carefully before proceeding.")
        else:
            recommendations.append("The website appears legitimate based on our analysis.")
            if features.get('AgeofDomain', 0) == 1:
                recommendations.append("The domain has been registered for a significant period, which is a positive signal.")
            if features.get('DNSRecording', 0) == 1 and features.get('PageRank', 0) == 1:
                recommendations.append("The website has proper DNS configuration, indicating proper setup.")
        
        # general recommendations
        recommendations.append("Always verify the domain matches the website you intend to visit.")
        
        return recommendations
    
    def _get_explanation(self, is_phishing: bool, threat_score: int, features: Dict[str, Any]) -> str:
        domain_age = "unknown" if features.get('AgeofDomain', 0) == 0 else "established"
        protocol = "insecure HTTP" if features.get('uses_http', 1) == 1 else "secure HTTPS"
        
        if is_phishing:
            if threat_score > 85:
                explanation = f"This URL has been identified as a high-risk phishing website with {threat_score}% confidence. "
                explanation += f"It uses {protocol} and has an {domain_age} domain age. "
                explanation += "Multiple phishing indicators were detected including "
                
                indicators = []
                if features.get('IsTyposquatting', 0) == 1:
                    indicators.append("typosquatting")
                if features.get('BrandInSubdomain', 0) == 1:
                    indicators.append("brand impersonation in the subdomain")
                if features.get('ultra_high_risk', 0) == 1:
                    indicators.append("ultra-high risk patterns")
                if not indicators:
                    indicators.append("suspicious URL patterns")
                
                explanation += ", ".join(indicators) + "."
                return explanation
            else:
                return f"This URL appears to be a phishing website with {threat_score}% confidence. It uses {protocol} and shows several concerning patterns including {'typosquatting' if features.get('IsTyposquatting', 0) == 1 else 'suspicious URL structure'}."
        elif threat_score >= 30:
            return f"This URL shows suspicious characteristics with {threat_score}% risk score. While not conclusively malicious, it uses {protocol} and has some concerning patterns that warrant caution."
        else:
            if threat_score < 15:
                return f"This URL appears to be entirely legitimate with very low phishing probability ({threat_score}%). It uses {protocol}, has an {domain_age} domain age, and shows no suspicious patterns."
            else:
                return f"This URL appears to be legitimate with low phishing probability ({threat_score}%). It uses {protocol} and shows minimal suspicious patterns."
    
    def predict(self, url: str, features: Optional[Dict[str, Any]] = None) -> ChatbotURLResponse:
        try:
            # check if we have cached results for this URL
            if self.redis.is_connected():
                cached_result = self.redis.get_cached_analysis(url)
                if cached_result:
                    logger.info(f"Using cached analysis result for URL: {url[:50]}...")
                    return ChatbotURLResponse(**cached_result)
                
            # check if model is loaded
            if self.model is None:
                logger.error("Chatbot model not loaded")
                raise RuntimeError("Model not loaded")
            
            # extract features if not provided
            if features is None:
                features = FeatureExtractor.extract_features(url)
            
            logger.info(f"Features extracted for URL: {url[:50]}...")
            
            # prepare features for the model
            if self.feature_list:
                # use feature list to ensure correct order
                X = FeatureExtractor.prepare_features_for_model(features, self.feature_list)
                logger.info(f"Prepared feature array shape: {X.shape}")
            else:
                # fallback if feature list is not available
                X = np.array(list(features.values())).reshape(1, -1)
                logger.warning("No feature list available, using all features")
            
            # scale features
            if self.scaler:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X
                logger.warning("No scaler available, using raw features")
            
            # make prediction
            raw_prediction = self.model.predict(X_scaled)[0]
            raw_probability = float(self.model.predict_proba(X_scaled)[0, 1])
            
            logger.info(f"Raw model output: prediction={raw_prediction}, probability={raw_probability:.4f}")
            
            # ultra-high recall threshold for chatbot safety 
            phishing_threshold = 0.4  # lower threshold for maximum security
            warning_threshold = float(WARNING_THRESHOLD_CB) if WARNING_THRESHOLD_CB else 0.3
            
            # ultra-sensitive override
            ultra_sensitive_override = (
                features.get('UsingIP', 0) == 1 or 
                features.get('ultra_high_risk', 0) == 1 or
                features.get('IsTyposquatting', 0) == 1 or
                features.get('BrandInSubdomain', 0) == 1
            )
            
            # apply the threshold to determine if it's phishing
            is_phishing = raw_probability >= phishing_threshold or ultra_sensitive_override
            is_suspicious = raw_probability >= warning_threshold
            
            # calculate threat score based on raw probability
            threat_score = int(raw_probability * 100)
            
            # boost threat score for ultra-sensitive cases
            if ultra_sensitive_override:
                threat_score = max(threat_score, 85)
                logger.info("Ultra-sensitive override: Critical phishing indicators detected")
            
            # determine confidence level
            if threat_score > 85 or threat_score < 15:
                confidence_level = "High"
            elif 30 <= threat_score <= 70:
                confidence_level = "Medium"
            else:
                confidence_level = "Low"
            
            # get features that were analyzed
            features_analyzed = [
                "domain_age", "ssl_cert", "url_length", 
                "special_chars", "typosquatting", "subdomains",
                "dns_records", "domain_registration", "brand_impersonation",
                "ultra_comprehensive_analysis"
            ]
            
            # generate deep analysis
            deep_analysis = self._get_deep_analysis(url, features, raw_probability)
            
            # generate recommendations
            recommendations = self._get_recommendations(is_phishing, threat_score, features)
            
            # generate explanation
            explanation = self._get_explanation(is_phishing, threat_score, features)
            
            # build the response
            response = ChatbotURLResponse(
                url=url,
                is_phishing=is_phishing,
                threat_score=threat_score,
                probability=raw_probability,
                analysis_timestamp=datetime.now(),
                confidence_level=confidence_level,
                features_analyzed=features_analyzed,
                model_version=self.model_info['version'],
                deep_analysis=deep_analysis,
                recommendations=recommendations,
                explanation=explanation
            )

            # cache the result if Redis is connected
            if self.redis.is_connected():
                self.redis.cache_url_analysis(url, response.dict())

            # track the model evaluation in the database if available
            if hasattr(self, 'db_integration'):
                # Track this evaluation
                self.db_integration.track_model_evaluation({
                    "model_name": self.model_info["name"],
                    "url": url,
                    "is_phishing": is_phishing,
                    "score": threat_score / 100.0  # Convert to 0-1 range
                })
            
            return response
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}", exc_info=True)
            raise
    
    def process_feedback(self, url: str, feedback_type: str, reported_by: Optional[str] = None) -> bool:
        """process user feedback about an analysis for continuous learning"""
        try:
            # determine actual phishing status based on feedback type
            is_phishing = feedback_type in ['false_negative', 'confirm_phishing']
            
            # store in redis for later processing if redis is connected
            if self.redis.is_connected():
                self.redis.store_feedback(url, is_phishing, feedback_type)
                logger.info(f"Stored {feedback_type} feedback for {url[:30]}...")
                return True
            else:
                logger.warning("Redis not connected, feedback not stored")
                return False
                
        except Exception as e:
            logger.error(f"Error processing feedback: {str(e)}")
            return False