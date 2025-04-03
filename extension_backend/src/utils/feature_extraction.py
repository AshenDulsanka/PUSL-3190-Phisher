import re
from urllib.parse import urlparse
import numpy as np
from ..logging_config import get_logger

logger = get_logger(__name__)

class FeatureExtractor:
    """Utility class for extracting lightweight features for browser extension"""
    
    @staticmethod
    def extract_features(url):
        try:
            features = {}
            
            # URL Length
            features['url_length'] = len(url)
            
            # number of dots in domain
            features['num_dots'] = url.count('.')
            
            # number of special characters
            features['num_special_chars'] = sum(c in "!@#$%^&*()_+-=[]{}|;:,<>?/" for c in url)
            
            # get domain and path
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                path = parsed.path
            except:
                domain = url.split('/')[0] if '/' in url else url
                path = '/'.join(url.split('/')[1:]) if '/' in url else ''
            
            # presence of IP address (simple check for 4 numbers separated by dots)
            features['has_ip'] = 1 if bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)) else 0
            
            # presence of @ symbol
            features['has_at_symbol'] = 1 if '@' in url else 0
            
            # number of subdomains
            subdomain_count = len(domain.split('.')) - 1 if domain else 0
            features['num_subdomains'] = subdomain_count
            
            # use of HTTPS
            features['has_https'] = 1 if url.startswith('https') else 0
            
            # presence of hyphens in domain
            features['has_hyphen'] = 1 if '-' in domain else 0
            
            # URL shortener detection (these are some common URL shorteners)
            url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
            features['is_shortened'] = 1 if any(shortener in url for shortener in url_shorteners) else 0
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features for URL {url}: {str(e)}")
            # return default features in case of error
            return {
                'url_length': 0,
                'num_dots': 0,
                'num_special_chars': 0,
                'has_ip': 0,
                'has_at_symbol': 0,
                'num_subdomains': 0,
                'has_https': 0,
                'has_hyphen': 0,
                'is_shortened': 0
            }
    
    @staticmethod
    def prepare_features_for_model(features, feature_list):
        # create an array with features in the correct order
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
            
        return np.array(feature_array).reshape(1, -1)