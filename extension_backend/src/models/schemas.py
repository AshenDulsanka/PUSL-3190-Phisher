from typing import Dict, Any, Optional, List
from pydantic import BaseModel, HttpUrl, Field, validator
import validators

class URLAnalysisRequest(BaseModel):
    url: str
    features: Optional[Dict[str, Any]] = None
    client: Optional[str] = "unknown"
    
    @validator('url')
    def validate_url(cls, v):
        if not validators.url(v):
            raise ValueError('Invalid URL format')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "features": {
                    "url_length": 22,
                    "num_dots": 1,
                    "num_special_chars": 3
                },
                "client": "browser_extension"
            }
        }

class URLAnalysisResponse(BaseModel):
    url: str
    is_phishing: bool
    threat_score: int = Field(..., ge=0, le=100)
    probability: float = Field(..., ge=0, le=1)
    details: str
    features_used: Optional[List[str]] = None
    model_version: str
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "is_phishing": False,
                "threat_score": 15,
                "probability": 0.15,
                "details": "This URL has been analyzed and appears to be legitimate.",
                "features_used": ["url_length", "num_dots", "num_special_chars"],
                "model_version": "random_forest_v1"
            }
        }

class ErrorResponse(BaseModel):
    detail: str
    
    class Config:
        schema_extra = {
            "example": {
                "detail": "An error occurred while processing the request"
            }
        }