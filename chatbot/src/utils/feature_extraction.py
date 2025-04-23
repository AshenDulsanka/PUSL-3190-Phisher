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

    @staticmethod
    def _extract_url_features(url: str) -> Dict[str, Any]:
        """extract basic features from URL string"""
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # basic URL features
        features = {
            "url_length": len(url),
            "num_dots": url.count('.'),
            "num_special_chars": len(re.findall(r'[^a-zA-Z0-9\.]', url)),
            "has_ip": 1 if DeepFeatureExtractor._is_ip(parsed_url.netloc) else 0,
            "has_at_symbol": 1 if '@' in url else 0,
            "has_hyphen": 1 if '-' in parsed_url.netloc else 0,
            "num_hyphens": parsed_url.netloc.count('-'),
            "num_underscores": url.count('_'),
            "num_percent": url.count('%'),
            "num_query_components": len(query.split('&')) if query else 0,
            "num_path_components": len(path.split('/')) if path else 0,
            "has_https": 1 if parsed_url.scheme == 'https' else 0,
        }
        
        # URL shortening service detection
        shortening_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'ow.ly']
        features["is_shortened"] = 1 if any(service in parsed_url.netloc for service in shortening_services) else 0
        
        # number of subdomains
        ext = tldextract.extract(url)
        subdomain = ext.subdomain
        features["num_subdomains"] = len(subdomain.split('.')) if subdomain else 0
        
        return features
    
    @staticmethod
    def _extract_domain_features(url: str) -> Dict[str, Any]:
        """extract features related to the domain"""
        features = {}
        
        try:
            # get domain details
            ext = tldextract.extract(url)
            domain = ext.domain
            suffix = ext.suffix
            
            if domain and suffix:
                # domain age (in days)
                try:
                    domain_info = whois.whois(f"{domain}.{suffix}")
                    if domain_info.creation_date:
                        # handle both single and multiple creation dates
                        if isinstance(domain_info.creation_date, list):
                            creation_date = domain_info.creation_date[0]
                        else:
                            creation_date = domain_info.creation_date
                            
                        domain_age = (datetime.now() - creation_date).days
                        features["domain_age"] = domain_age
                    else:
                        features["domain_age"] = 0
                except Exception:
                    features["domain_age"] = 0
            
            # check if domain is in Alexa top 1M (simplified)
            features["domain_in_alexa_top_1m"] = 0  # Default to 0
                
        except Exception as e:
            logger.warning(f"Error extracting domain features: {e}")
            features["domain_age"] = 0
            features["domain_in_alexa_top_1m"] = 0
            
        return features