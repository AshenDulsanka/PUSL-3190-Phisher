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
    
    @staticmethod
    def extract_comprehensive_features(url, additional_data=None):
        """
        Extract comprehensive features for deep analysis in the chatbot
        
        Args:
            url (str): The URL to analyze
            additional_data (dict, optional): Additional data about the URL if available
            
        Returns:
            dict: Dictionary of extracted features
        """
        # Start with lightweight features
        features = FeatureExtractor.extract_lightweight_features(url)
        
        # Need to all the features
        
        # Get domain and path
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except:
            domain = url.split('/')[0] if '/' in url else url
            path = '/'.join(url.split('/')[1:]) if '/' in url else ''
            
        # Suspicious TLD - Common phishing TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
        features['suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
        
        # Suspicious keywords in URL
        suspicious_keywords = ['secure', 'account', 'webscr', 'login', 'signin', 'verify', 'banking']
        features['suspicious_keywords'] = sum(keyword in url.lower() for keyword in suspicious_keywords)
        
        # URL entropy (measure of randomness, higher in phishing URLs)
        def calculate_entropy(text):
            """Calculate Shannon entropy of a string"""
            if not text:
                return 0
            text = text.lower()
            p, counts = np.unique(list(text), return_counts=True)
            return -sum(count/len(text) * np.log2(count/len(text)) for count in counts)
        
        features['url_entropy'] = calculate_entropy(domain)
        
        # If additional_data is provided, use it
        if additional_data:
            if 'domain_age' in additional_data:
                features['domain_age'] = additional_data['domain_age']
            if 'ssl_validity' in additional_data:
                features['ssl_validity'] = additional_data['ssl_validity']
            # Add more as needed
        else:
            # Otherwise use placeholder values
            # In a real implementation, these would come from WHOIS, DNS, etc.
            features['domain_age'] = 0  # Unknown
            features['ssl_validity'] = 0  # Unknown
        
        return features

