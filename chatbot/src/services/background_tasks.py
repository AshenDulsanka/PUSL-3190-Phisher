import time
import threading
import schedule
from typing import Dict, Any

from ..logging_config import get_logger
from ..config import DB_SYNC_ENABLED
from .database_integration_service import DatabaseIntegrationService
from .redis_service import RedisService

logger = get_logger(__name__)

class BackgroundTasks:
    """service for running background tasks like database syncing"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BackgroundTasks, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.db_integration = DatabaseIntegrationService()
        self.redis = RedisService()
        self.running = False
        self.thread = None
    
    def start(self):
        """start background tasks"""
        if self.running:
            logger.warning("Background tasks are already running")
            return
            
        logger.info("Starting background tasks")
        self.running = True
        
        # schedule redis-to-DB sync every 5 minutes
        schedule.every(5).minutes.do(self.sync_redis_feedback)
        
        # start the background thread
        self.thread = threading.Thread(target=self._run_scheduler)
        self.thread.daemon = True
        self.thread.start()
    
    def _run_scheduler(self):
        """run the scheduler in a loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(1)
    
    def stop(self):
        """stop background tasks"""
        logger.info("Stopping background tasks")
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def sync_redis_feedback(self):
        """sync Redis feedback with database"""
        if not DB_SYNC_ENABLED:
            return
            
        logger.info("Running Redis feedback sync job")
        
        # check if Redis is connected
        if not self.redis.is_connected():
            logger.warning("Redis not connected, skipping sync")
            return
        
        # check queue size
        queue_size = self.redis.get_queue_size()
        if queue_size == 0:
            logger.info("No feedback to sync")
            return
            
        logger.info(f"Found {queue_size} feedback items to sync")
        
        # process in batches of 50
        batch_size = 50
        self.db_integration.sync_feedback_to_database(batch_size)