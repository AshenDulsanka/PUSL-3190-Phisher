import re
import urllib.parse
import numpy as np
import tldextract
import requests
from typing import Dict, Any, List
import socket
import ssl
import time
import whois
from bs4 import BeautifulSoup
from datetime import datetime
import logging
from ..logging_config import get_logger

logger = get_logger(__name__)

class DeepFeatureExtractor:
    """
    class for extracting comprehensive features from URLs for deep analysis
    """
    
    @staticmethod
    def extract_features(url: str) -> Dict[str, Any]:
        """
        extract all features from a URL for deep analysis
        """
        features = {}
        
        try:
            # basic URL features (shared with lightweight extractor)
            features.update(DeepFeatureExtractor._extract_url_features(url))
            
            # domain-based features
            features.update(DeepFeatureExtractor._extract_domain_features(url))
            
            # content-based features (requires downloading)
            try:
                features.update(DeepFeatureExtractor._extract_content_features(url))
            except Exception as e:
                logger.warning(f"Error extracting content features: {e}")
                # add defaults for content features
                features.update({
                    "has_iframe": 0,
                    "disables_right_click": 0,
                    "has_popup": 0,
                    "has_login_form": 0,
                    "forms_to_external": 0,
                    "external_js_ratio": 0,
                    "favicon_same_domain": 1
                })
                
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
        
        return features
    
