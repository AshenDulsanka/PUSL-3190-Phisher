from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from typing import Dict, Any
import time

from ..logging_config import get_logger
from ..models.schemas import URLAnalysisRequest, URLAnalysisResponse, ErrorResponse
from ..services.model_service import ModelService
from ..utils.feature_extraction import DeepFeatureExtractor

logger = get_logger(__name__)

router = APIRouter(tags=["Deep URL Analysis"])

# rate limiting tracker
request_counters: Dict[str, Dict[str, int]] = {}

# rate limiting dependency
async def check_rate_limit(request: Request, limit: int = 30):
    client_ip = request.client.host
    current_minute = int(time.time() / 60)
    
    # reset counters for new minute
    if client_ip in request_counters and current_minute > next(iter(request_counters[client_ip])):
        request_counters[client_ip] = {current_minute: 1}
    else:
        if client_ip not in request_counters:
            request_counters[client_ip] = {current_minute: 1}
        else:
            if current_minute in request_counters[client_ip]:
                request_counters[client_ip][current_minute] += 1
            else:
                request_counters[client_ip][current_minute] = 1
    
    # check if limit exceeded
    if request_counters[client_ip][current_minute] > limit:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests"
        )

@router.post(
    "/deep-analyze-url",
    response_model=URLAnalysisResponse,
    responses={
        status.HTTP_429_TOO_MANY_REQUESTS: {"model": ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse}
    }
)
async def deep_analyze_url(
    request_data: URLAnalysisRequest,
    request: Request,
    _: None = Depends(check_rate_limit)
):
    """
    analyze URL using the Gradient Boosting model with deep feature extraction
    """
    start_time = time.time()
    
    try:
        logger.info(f"Deep analyzing URL: {request_data.url[:50]}... from client: {request_data.client}")
        
        # get model service (singleton)
        model_service = ModelService()
        
        # use client-provided features or extract them
        features = request_data.features if request_data.features else DeepFeatureExtractor.extract_features(request_data.url)
        
        # make prediction
        result = model_service.predict(request_data.url, features)
        
        # log result
        process_time = time.time() - start_time
        is_phishing = result.get("is_phishing", False)
        threat_score = result.get("threat_score", 0)
        
        logger.info(
            f"URL deep analysis result: is_phishing={is_phishing}, "
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
            features=result.get("features", None),
            features_used=result.get("features_used", None),
            model_version=result.get("model_version", "gradient_boost")
        )
        
    except ValueError as e:
        logger.warning(f"Invalid request for URL deep analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
        
    except Exception as e:
        logger.error(f"Error deep analyzing URL: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the URL"
        )