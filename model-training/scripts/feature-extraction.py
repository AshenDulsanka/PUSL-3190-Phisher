import re
import numpy as np
from urllib.parse import urlparse

class FeatureExtractor:
    """
    Utility class to extract features from URLs for phishing detection
    """
    
    @staticmethod
    def extract_lightweight_features(url):
        """
        Extract lightweight features suitable for browser extension
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Dictionary of extracted features
        """
        features = {}
        
        # URL Length
        features['url_length'] = len(url)
        
        # Number of dots in domain
        features['num_dots'] = url.count('.')
        
        # Number of special characters (!@#$%^&*()_+)
        features['num_special_chars'] = sum(c in "!@#$%^&*()_+-=[]{}|;:,<>?/" for c in url)
        
        # Presence of IP address (simple check for 4 numbers separated by dots)
        features['has_ip'] = 1 if bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)) else 0
        
        # Presence of @ symbol
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # Get domain and path
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except:
            domain = url.split('/')[0] if '/' in url else url
            path = '/'.join(url.split('/')[1:]) if '/' in url else ''
        
        # Number of subdomains
        subdomain_count = len(domain.split('.')) - 1 if domain else 0
        features['num_subdomains'] = subdomain_count
        
        # Use of HTTPS
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # Presence of hyphens in domain
        features['has_hyphen'] = 1 if '-' in domain else 0
        
        # URL shortener detection (common URL shorteners)
        url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
        features['is_shortened'] = 1 if any(shortener in url for shortener in url_shorteners) else 0
        
        return features
