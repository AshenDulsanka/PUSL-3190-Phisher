from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel, HttpUrl, Field, validator
import validators
from datetime import datetime

class ChatbotURLRequest(BaseModel):
    """Request model for URL analysis by the chatbot"""
    url: str
    client_info: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    previous_detection: Optional[Dict[str, Any]] = None
    
    @validator('url')
    def validate_url(cls, v):
        if not validators.url(v):
            raise ValueError('Invalid URL format')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "client_info": {
                    "browser": "Chrome",
                    "version": "91.0.4472.124",
                    "platform": "Windows"
                },
                "session_id": "abc-123-xyz",
                "previous_detection": {
                    "threat_score": 35,
                    "is_phishing": False
                }
            }
        }

class DeepAnalysisResult(BaseModel):
    """Model for detailed URL analysis results"""
    domain_age_days: Optional[int] = None
    registration_details: Optional[Dict[str, Any]] = None
    dns_records: Optional[Dict[str, Any]] = None
    security_signals: Optional[Dict[str, bool]] = None
    content_analysis: Optional[Dict[str, Any]] = None
    typosquatting_info: Optional[Dict[str, Any]] = None
    brand_impersonation: Optional[Dict[str, Any]] = None

class ChatbotURLResponse(BaseModel):
    """Response model for detailed URL analysis"""
    url: str
    is_phishing: bool
    threat_score: int = Field(..., ge=0, le=100)
    probability: float = Field(..., ge=0, le=1)
    analysis_timestamp: datetime = Field(default_factory=datetime.now)
    confidence_level: str  # High, Medium, Low
    features_analyzed: List[str]
    model_version: str
    deep_analysis: DeepAnalysisResult
    recommendations: List[str]
    explanation: str
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "is_phishing": False,
                "threat_score": 15,
                "probability": 0.15,
                "analysis_timestamp": "2023-05-15T10:30:45",
                "confidence_level": "High",
                "features_analyzed": [
                    "domain_age", "ssl_cert", "url_length", 
                    "special_chars", "typosquatting"
                ],
                "model_version": "random_forest_v2.0",
                "deep_analysis": {
                    "domain_age_days": 3650,
                    "registration_details": {
                        "registrar": "Example Registrar Inc.",
                        "creation_date": "2013-05-15"
                    },
                    "dns_records": {
                        "has_mx": True,
                        "has_spf": True,
                        "has_dmarc": True
                    },
                    "security_signals": {
                        "uses_https": True,
                        "valid_certificate": True,
                        "suspicious_redirects": False
                    },
                    "content_analysis": {
                        "form_count": 0,
                        "external_links": 2,
                        "iframe_count": 0
                    },
                    "typosquatting_info": {
                        "is_typosquatting": False
                    },
                    "brand_impersonation": {
                        "detected": False
                    }
                },
                "recommendations": [
                    "The website appears legitimate.",
                    "Always verify the domain matches the expected website."
                ],
                "explanation": "This URL has been analyzed and appears to be legitimate. The domain has been registered for over 10 years, has proper SSL configuration, and shows no signs of phishing tactics."
            }
        }

class ChatMessage(BaseModel):
    content: str
    is_user: bool
    timestamp: datetime = Field(default_factory=datetime.now)

class ChatSession(BaseModel):
    session_id: str
    messages: List[ChatMessage] = []
    start_time: datetime = Field(default_factory=datetime.now)
    last_activity: datetime = Field(default_factory=datetime.now)
    analyzed_url: Optional[str] = None
    
class ErrorResponse(BaseModel):
    detail: str
    
    class Config:
        schema_extra = {
            "example": {
                "detail": "An error occurred while processing the request"
            }
        }

class HealthCheckResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.now)