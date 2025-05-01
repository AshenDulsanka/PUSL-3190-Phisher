import requests
import json
import time
from typing import Dict, Any, List
import logging

from ..logging_config import get_logger
from ..config import WEB_SERVER_URL
from .redis_service import RedisService

logger = get_logger(__name__)

class DatabaseIntegrationService:
    """service for integrating Redis data with the database"""
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
        self.redis = RedisService()
        
    def save_url_analysis(self, url_data: Dict[str, Any]) -> bool:
        """save URL analysis to the database via the API"""
        try:
            # extract the needed data from the result
            data = {
                "url": url_data.get("url"),
                "is_phishing": url_data.get("is_phishing"),
                "threat_score": url_data.get("threat_score", 0),
                "source": "chatbot",
                "features": {
                    "domain_age": url_data.get("deep_analysis", {}).get("domain_age_days"),
                    "hasHTTPS": not url_data.get("deep_analysis", {}).get("security_signals", {}).get("uses_https", True),
                    "hasIframe": url_data.get("deep_analysis", {}).get("content_analysis", {}).get("iframe_count", 0) > 0
                }
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
    
    def sync_feedback_to_database(self, batch_size: int = 20) -> bool:
        """synchronize feedback data from Redis to the database"""
        if not self.redis.is_connected():
            logger.warning("Redis not connected, cannot sync feedback")
            return False
            
        try:
            # get batch of feedback from Redis
            feedback_batch = self.redis.get_learning_batch(batch_size)
            
            if not feedback_batch:
                logger.debug("No feedback to sync with database")
                return True
                
            logger.info(f"Syncing {len(feedback_batch)} feedback items with database")
            
            # send the batch to the database
            response = requests.post(
                f"{WEB_SERVER_URL}/api/url/internal/process-feedback-batch",
                json={"feedback_batch": feedback_batch},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                processed_count = sum(1 for item in result.get("results", []) if item.get("success", False))
                
                # if any were successfully processed, remove them from Redis
                if processed_count > 0:
                    logger.info(f"Successfully processed {processed_count} feedback items")
                    self.redis.confirm_batch_processed(processed_count)
                
                return True
            else:
                logger.error(f"Failed to sync feedback with database: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error syncing feedback with database: {str(e)}")
            return False
    
    def log_system_event(self, level: str, message: str, metadata: Dict[str, Any] = None) -> bool:
        """log a system event to the database"""
        try:
            data = {
                "component": "chatbot",
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