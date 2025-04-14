from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from typing import Dict, Any
import time

from ..logging_config import get_logger
from ..models.schemas import URLAnalysisRequest, URLAnalysisResponse, ErrorResponse
from ..services.model_service import ModelService
from ..utils.feature_extraction import FeatureExtractor

logger = get_logger(__name__)

router = APIRouter(tags=["URL Analysis"])

# rate limiting tracker
request_counters: Dict[str, Dict[str, int]] = {}

# rate limiting dependency
async def check_rate_limit(request: Request, limit: int = 60):
    client_ip = request.client.host
    current_minute = int(time.time() / 60)
    
    # initialize counter for this minute if needed
    if current_minute not in request_counters:
        request_counters.clear()  # Clear old data
        request_counters[current_minute] = {}
    
    # initialize counter for this client if needed
    if client_ip not in request_counters[current_minute]:
        request_counters[current_minute][client_ip] = 0
    
    # check if limit exceeded
    if request_counters[current_minute][client_ip] >= limit:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    # increment counter
    request_counters[current_minute][client_ip] += 1

@router.post(
    "/analyze-url",
    response_model=URLAnalysisResponse,
    responses={
        status.HTTP_429_TOO_MANY_REQUESTS: {"model": ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse}
    }
)
async def analyze_url(
    request_data: URLAnalysisRequest,
    request: Request,
    _: None = Depends(check_rate_limit)
):
    start_time = time.time()
    
    try:
        logger.info(f"Analyzing URL: {request_data.url[:50]}... from client: {request_data.client}")
        
        # get model service (singleton)
        model_service = ModelService()
        
        # use client-provided features or extract them
        features = FeatureExtractor.extract_features(request_data.url)
        
        # make prediction
        result = model_service.predict(request_data.url, features)
        
        # log result
        process_time = time.time() - start_time
        is_phishing = result.get("is_phishing", False)
        threat_score = result.get("threat_score", 0)
        
        logger.info(
            f"URL analysis result: is_phishing={is_phishing}, "
            f"threat_score={threat_score}, "
            f"time={process_time:.4f}s"
        )
        
        # return response
        return URLAnalysisResponse(
            url=request_data.url,
            is_phishing=is_phishing,
            threat_score=threat_score,
            probability=result.get("probability", 0.0),
            details=result.get("details", "URL analyzed successfully"),
            features_used=result.get("features_used", None),
            model_version=result.get("model_version", "unknown")
        )
        
    except ValueError as e:
        logger.warning(f"Invalid request for URL analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the URL"
        )