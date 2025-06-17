import re
import tldextract
from urllib.parse import urlparse
import math
import numpy as np
from ..logging_config import get_logger

logger = get_logger(__name__)

class FeatureExtractor:
    @staticmethod
    def extract_features(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            features = {}
            
            # Basic fast features (matching notebook)
            features['url_length'] = len(url)
            features['num_dots'] = url.count('.')
            features['has_https'] = 1 if url.startswith('https') else 0
            features['has_at_symbol'] = 1 if '@' in url else 0
            
            # IP detection
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            features['has_ip'] = 1 if ip_pattern.search(domain) else 0
            
            # Domain analysis
            features['domain_length'] = len(domain)
            features['has_hyphen'] = 1 if '-' in domain else 0
            
            # TLD and subdomain analysis
            extracted = tldextract.extract(url)
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['suspicious_tld'] = 1 if extracted.suffix in {'tk', 'ml', 'ga', 'cf', 'gq'} else 0
            
            # URL shortener detection
            features['url_shortener'] = 1 if any(s in domain for s in {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly'}) else 0
            
            # Character analysis
            features['special_char_ratio'] = len([c for c in url if not c.isalnum() and c != '.']) / len(url)
            
            # Keyword analysis
            features['suspicious_keywords'] = sum(1 for kw in {'verify', 'secure', 'account', 'login'} if kw in url.lower())
            features['brand_keywords'] = sum(1 for brand in {'paypal', 'amazon', 'google'} if brand in extracted.domain.lower())
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features for URL {url}: {str(e)}")
            # Return safe defaults
            return {
                'url_length': 0, 'num_dots': 0, 'has_https': 0, 'has_at_symbol': 0,
                'has_ip': 0, 'domain_length': 0, 'has_hyphen': 0, 'subdomain_count': 0,
                'suspicious_tld': 0, 'url_shortener': 0, 'special_char_ratio': 0,
                'suspicious_keywords': 0, 'brand_keywords': 0
            }
    
    @staticmethod
    def prepare_features_for_model(features, feature_list):
        """Prepare features in the correct order for the model"""
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
        return np.array(feature_array).reshape(1, -1)