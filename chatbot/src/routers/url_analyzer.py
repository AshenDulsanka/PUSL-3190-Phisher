from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
import time
from typing import Dict, Any, List, Optional

from ..logging_config import get_logger
from ..models.schemas import ChatbotURLRequest, ChatbotURLResponse, ErrorResponse
from ..services.model_service import ModelService
from ..utils.feature_extraction import FeatureExtractor
from ..models.schemas import FeedbackRequest
from ..services.database_integration_service import DatabaseIntegrationService
from ..config import RATE_LIMIT_PER_MINUTE, DB_SYNC_ENABLED

logger = get_logger(__name__)

router = APIRouter(tags=["Chatbot Analysis"])

# initialize the service
db_integration = DatabaseIntegrationService()

# rate limiting tracker
request_counters: Dict[str, Dict[str, int]] = {}

async def check_rate_limit(request: Request, limit: int = RATE_LIMIT_PER_MINUTE):
    """rate limiting dependency"""
    client_ip = request.client.host
    current_time = int(time.time() / 60)  # current minute
    
    # initialize or clean up old entries
    if client_ip not in request_counters:
        request_counters[client_ip] = {}
    
    # clean old minute counters
    old_minutes = [minute for minute in request_counters[client_ip] if minute != current_time]
    for minute in old_minutes:
        del request_counters[client_ip][minute]
    
    # increment counter
    request_counters[client_ip][current_time] = request_counters[client_ip].get(current_time, 0) + 1
    
    # check limit
    if request_counters[client_ip][current_time] > limit:
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit} requests per minute."
        )

@router.post(
    "/deep-analyze-url",
    response_model=ChatbotURLResponse,
    responses={
        status.HTTP_429_TOO_MANY_REQUESTS: {"model": ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse}
    }
)
async def analyze_url(
    request_data: ChatbotURLRequest,
    request: Request,
    _: None = Depends(check_rate_limit)
):
    """
    deep analysis of a URL for phishing detection with detailed explanation
    """
    try:
        start_time = time.time()
        url = request_data.url
        
        logger.info(f"Chatbot analysis request received for URL: {url[:50]}...")
        
        # get model service (singleton)
        model_service = ModelService()
        
        # get comprehensive analysis
        response = model_service.predict(url)

        # save to database
        if DB_SYNC_ENABLED:
            db_integration.save_url_analysis(response.dict())
        
        # log the result
        elapsed = time.time() - start_time
        logger.info(
            f"Analysis completed in {elapsed:.2f}s: "
            f"URL={url[:50]}, "
            f"is_phishing={response.is_phishing}, "
            f"score={response.threat_score}"
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during analysis. Please try again later."
        )