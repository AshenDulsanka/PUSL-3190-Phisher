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
        """Extract high-performance features matching the notebook"""
        try:
            url_lower = url.lower()
            parsed = urlparse(url_lower)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            extracted = tldextract.extract(url)
            subdomain = extracted.subdomain or ''
            domain_name = extracted.domain or ''
            tld = extracted.suffix or ''
            
            # Match the exact features from the notebook
            features = {
                # Basic metrics
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(path),
                'query_length': len(query),
                
                # Security indicators  
                'has_https': 1 if url.startswith('https') else 0,
                'has_ip': 1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain) else 0,
                'has_at_symbol': 1 if '@' in url else 0,
                'has_double_slash': 1 if '//' in url[8:] else 0,
                
                # Domain analysis
                'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
                'long_subdomain': 1 if len(subdomain) > 25 else 0,
                'has_hyphen': 1 if '-' in domain_name else 0,
                'digit_ratio': sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1),
                
                # Character analysis
                'special_char_count': len(re.findall(r'[%\-_=&\?]', url)),
                'special_char_ratio': len(re.findall(r'[%\-_=&\?]', url)) / len(url),
                'dot_count': url.count('.'),
                'slash_count': url.count('/'),
                
                # Content analysis
                'keyword_count': sum(1 for kw in ['verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm', 'suspended', 'locked', 'expired', 'urgent', 'immediate', 'security', 'alert', 'warning', 'action', 'required', 'validation', 'authenticate', 'banking', 'payment', 'billing', 'invoice', 'transaction', 'refund', 'card', 'credit', 'debit', 'wallet', 'paypal', 'stripe', 'winner', 'prize', 'congratulations', 'claim', 'reward', 'gift', 'free', 'limited', 'offer', 'deal', 'discount', 'bonus', 'webscr', 'cgi-bin', 'gateway', 'portal', 'admin', 'control'] if kw in url_lower),
                'brand_impersonation': sum(1 for brand in ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'instagram', 'twitter', 'linkedin', 'youtube', 'netflix', 'spotify', 'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover', 'chase', 'wells', 'bofa', 'citi', 'usbank', 'hsbc', 'bank', 'credit', 'union', 'financial', 'ups', 'fedex', 'dhl', 'usps', 'ebay', 'alibaba', 'dropbox', 'adobe', 'zoom', 'skype', 'whatsapp', 'irs', 'gov', 'postal', 'social', 'medicare'] if brand in domain_name),
                
                # Structure analysis
                'excessive_dots': 1 if url.count('.') > 5 else 0,
                'deep_path': 1 if path.count('/') > 4 else 0,
                'long_query': 1 if len(query) > 100 else 0,
                'suspicious_tld': 1 if tld in ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'download', 'link', 'info', 'biz', 'xyz', 'club', 'online', 'site', 'website', 'space', 'tech', 'store', 'shop'] else 0,
                'is_shortener': 1 if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy', 'cutt.ly', 'bitly.com', 'short.io', 'rebrand.ly']) else 0,
                
                # Advanced features
                'homograph_risk': 1 if sum(1 for c in domain_name if ord(c) > 127) > 0 else 0,
                'url_entropy': len(set(url_lower)) / len(url) if len(url) > 0 else 0,
                'has_www': 1 if domain.startswith('www.') else 0,
                'port_in_url': 1 if ':' in domain and not domain.startswith('http') else 0
            }
            
            return features
        except Exception as e:
            # Return safe defaults
            return {k: 0 for k in ['url_length', 'domain_length', 'path_length', 'query_length', 'has_https', 'has_ip', 'has_at_symbol', 'has_double_slash', 'subdomain_count', 'long_subdomain', 'has_hyphen', 'digit_ratio', 'special_char_count', 'special_char_ratio', 'dot_count', 'slash_count', 'keyword_count', 'brand_impersonation', 'excessive_dots', 'deep_path', 'long_query', 'suspicious_tld', 'is_shortener', 'homograph_risk', 'url_entropy', 'has_www', 'port_in_url']}
    
    @staticmethod
    def prepare_features_for_model(features, feature_list):
        """Prepare features in the correct order for the model"""
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
        return np.array(feature_array).reshape(1, -1)