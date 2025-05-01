import json
import time
from typing import Dict, Any, Optional, List
import redis

from ..config import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB, REDIS_ENABLED
from ..logging_config import get_logger

logger = get_logger(__name__)

class RedisService:
    """service for Redis caching and continuous learning data storage"""
    _instance = None
    
    # constants for key prefixes
    URL_CACHE_PREFIX = "url_cache:"
    FEEDBACK_PREFIX = "feedback:"
    ANALYSIS_HISTORY_PREFIX = "analysis_history:"
    LEARNING_QUEUE_KEY = "learning_queue"
    
    # TTL values (in seconds)
    URL_CACHE_TTL = 60 * 60 * 24 * 7  # 7 days for URL analysis cache
    FEEDBACK_TTL = 60 * 60 * 24 * 30   # 30 days for user feedback
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedisService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.enabled = REDIS_ENABLED
        self.client = None
        
        if not self.enabled:
            logger.info("Redis is disabled in configuration")
            return
            
        try:
            self.client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                db=REDIS_DB,
                decode_responses=True,
                socket_timeout=5
            )
            self.client.ping()  # test the connection
            logger.info(f"Redis connection established to {REDIS_HOST}:{REDIS_PORT}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self.client = None
            
    def is_connected(self) -> bool:
        """check if Redis is connected and enabled"""
        if not self.enabled or self.client is None:
            return False
        try:
            return self.client.ping()
        except:
            return False
            
    def cache_url_analysis(self, url: str, analysis_result: Dict[str, Any]) -> bool:
        """cache the analysis result for a URL"""
        if not self.is_connected():
            return False
            
        try:
            key = f"{self.URL_CACHE_PREFIX}{url}"
            value = json.dumps(analysis_result)
            
            self.client.set(key, value, ex=self.URL_CACHE_TTL)
            logger.debug(f"Cached analysis for URL: {url[:30]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to cache URL analysis: {str(e)}")
            return False
            
    def get_cached_analysis(self, url: str) -> Optional[Dict[str, Any]]:
        """get cached analysis result for a URL"""
        if not self.is_connected():
            return None
            
        try:
            key = f"{self.URL_CACHE_PREFIX}{url}"
            cached = self.client.get(key)
            
            if cached:
                logger.debug(f"Cache hit for URL: {url[:30]}...")
                return json.loads(cached)
            else:
                logger.debug(f"Cache miss for URL: {url[:30]}...")
                return None
        except Exception as e:
            logger.error(f"Failed to retrieve cached analysis: {str(e)}")
            return None
            
    def store_feedback(self, url: str, is_phishing: bool, feedback_type: str) -> bool:
        """store user feedback for continuous learning"""
        if not self.is_connected():
            return False
            
        try:
            feedback_data = {
                "url": url,
                "is_phishing": is_phishing,
                "feedback_type": feedback_type,
                "timestamp": time.time()
            }
            
            # store individual feedback
            feedback_key = f"{self.FEEDBACK_PREFIX}{url}"
            self.client.set(feedback_key, json.dumps(feedback_data), ex=self.FEEDBACK_TTL)
            
            # add to learning queue for batch processing
            self.client.lpush(self.LEARNING_QUEUE_KEY, json.dumps(feedback_data))
            
            logger.info(f"Stored {feedback_type} feedback for URL: {url[:30]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to store feedback: {str(e)}")
            return False
            
    def get_learning_batch(self, batch_size: int = 100) -> List[Dict[str, Any]]:
        """get a batch of feedback data for model retraining"""
        if not self.is_connected():
            return []
            
        try:
            batch = []
            for _ in range(batch_size):
                #get feedback data without removing from queue (we'll process in batches)
                item = self.client.lindex(self.LEARNING_QUEUE_KEY, 0)
                if item:
                    batch.append(json.loads(item))
                else:
                    break
            
            logger.info(f"Retrieved {len(batch)} items for learning batch")
            return batch
        except Exception as e:
            logger.error(f"Failed to get learning batch: {str(e)}")
            return []
            
    def confirm_batch_processed(self, count: int) -> bool:
        """remove processed items from the learning queue"""
        if not self.is_connected() or count <= 0:
            return False
            
        try:
            for _ in range(count):
                self.client.lpop(self.LEARNING_QUEUE_KEY)
                
            logger.info(f"Removed {count} processed items from learning queue")
            return True
        except Exception as e:
            logger.error(f"Failed to remove processed items: {str(e)}")
            return False
            
    def get_queue_size(self) -> int:
        """get the current size of the learning queue"""
        if not self.is_connected():
            return 0
            
        try:
            return self.client.llen(self.LEARNING_QUEUE_KEY)
        except Exception as e:
            logger.error(f"Failed to get queue size: {str(e)}")
            return 0