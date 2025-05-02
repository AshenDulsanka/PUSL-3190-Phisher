import requests
import json
import time
from typing import Dict, Any, List
import logging

from ..logging_config import get_logger
from ..config import WEB_SERVER_URL

logger = get_logger(__name__)

class DatabaseIntegrationService:
    """service for integrating extension data with the database"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseIntegrationService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        
    def save_url_analysis(self, url_data: Dict[str, Any], features: Dict[str, Any] = None) -> bool:
        """save URL analysis to the database via the API="""
        try:
            # extract the needed data 
            data = {
                "url": url_data.get("url"),
                "is_phishing": url_data.get("is_phishing"),
                "threat_score": url_data.get("threat_score", 0),
                "source": "browser_extension",
                "features": features or {}
            }
            
            # make API call to save the data
            response = requests.post(
                f"{WEB_SERVER_URL}/api/url/internal/save-analysis",
                json=data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Saved analysis for URL {url_data.get('url')[:30]}... to database")
                return True
            else:
                logger.error(f"Failed to save analysis to database: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error saving URL analysis to database: {str(e)}")
            return False
    
    def save_feedback(self, feedback_data: Dict[str, Any]) -> bool:
        """save feedback to the database"""
        try:
            # format the data for the API
            data = {
                "url": feedback_data.get("url"),
                "reportType": feedback_data.get("feedback_type"),
                "comments": feedback_data.get("comments", ""),
                "reporterEmail": feedback_data.get("reported_by", ""),
                "source": "browser_extension"
            }
            
            # make API call to save the data
            response = requests.post(
                f"{WEB_SERVER_URL}/api/url/report",
                json=data,
                headers={"Content-Type": "application/json"}
            )
            
            return response.status_code == 200 or response.status_code == 201
        except Exception as e:
            logger.error(f"Error saving feedback to database: {str(e)}")
            return False
    
    def log_system_event(self, level: str, message: str, metadata: Dict[str, Any] = None) -> bool:
        """log a system event to the database"""
        try:
            data = {
                "component": "extension_backend",
                "logLevel": level,
                "message": message,
                "metadata": json.dumps(metadata) if metadata else None
            }
            
            response = requests.post(
                f"{WEB_SERVER_URL}/api/log/system",
                json=data,
                headers={"Content-Type": "application/json"}
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error logging system event to database: {str(e)}")
            return False
    
    def register_lightweight_model(self, model_data: Dict[str, Any]) -> bool:
        """register or update a model in the database"""
        try:
            data = {
                "name": model_data.get("name"),
                "type": model_data.get("type", "unknown"),
                "version": model_data.get("version", "1.0"),
                "parameters": model_data.get("parameters")
            }
            
            response = requests.post(
                f"{WEB_SERVER_URL}/api/model/register",
                json=data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Registered model {data['name']} in database")
                return True
            else:
                logger.error(f"Failed to register model: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error registering model: {str(e)}")
            return False
    
    def track_lightweight_model_evaluation(self, eval_data: Dict[str, Any]) -> bool:
        """track a model evaluation"""
        try:
            data = {
                "model_name": eval_data.get("model_name"),
                "url": eval_data.get("url"),
                "predicted_score": eval_data.get("score"),
                "actual_label": eval_data.get("actual_label", None)
            }
            
            response = requests.post(
                f"{WEB_SERVER_URL}/api/model/evaluation",
                json=data,
                headers={"Content-Type": "application/json"}
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error tracking model evaluation: {str(e)}")
            return False