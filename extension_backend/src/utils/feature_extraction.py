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
        """Extract research-grade optimized features"""
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
            
            # Research-grade optimized features
            features = {
                # Critical security indicators
                'has_ip': 1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain) else 0,
                'has_https': 1 if url.startswith('https') else 0,
                'suspicious_tld': 1 if tld in ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click'] else 0,
                
                # Domain analysis
                'domain_length': len(domain_name),
                'suspiciously_short_domain': 1 if 0 < len(domain_name) < 4 else 0,
                'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
                'excessive_subdomains': 1 if (len(subdomain.split('.')) if subdomain else 0) > 3 else 0,
                'has_hyphen_in_domain': 1 if '-' in domain_name else 0,
                'high_digit_ratio': 1 if (sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)) > 0.3 else 0,
                
                # URL structure
                'url_length': len(url),
                'extremely_long_url': 1 if len(url) > 150 else 0,
                'deep_path': 1 if path.count('/') > 5 else 0,
                'long_query': 1 if len(query) > 50 else 0,
                
                # Content analysis
                'critical_keyword_count': sum(1 for kw in ['verify', 'secure', 'suspended', 'locked', 'expired', 'urgent', 'immediate', 'confirm', 'update', 'signin'] if kw in url_lower),
                'has_critical_keywords': 1 if sum(1 for kw in ['verify', 'secure', 'suspended', 'locked', 'expired', 'urgent', 'immediate', 'confirm', 'update', 'signin'] if kw in url_lower) >= 2 else 0,
                'has_brand_impersonation': 1 if sum(1 for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'instagram', 'twitter'] if brand in domain_name) > 0 else 0,
                'has_financial_keywords': 1 if sum(1 for kw in ['bank', 'payment', 'billing', 'card', 'wallet'] if kw in url_lower) > 0 else 0,
                
                # Suspicious patterns
                'is_shortener': 1 if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link']) else 0,
                'has_at_symbol': 1 if '@' in url else 0,
                'has_double_slash': 1 if '//' in url[8:] else 0,
                'special_char_density': len(re.findall(r'[%\-_=&\?]', url)) / len(url) if len(url) > 0 else 0,
                'high_special_char_density': 1 if (len(re.findall(r'[%\-_=&\?]', url)) / len(url) if len(url) > 0 else 0) > 0.15 else 0,
                
                # Advanced features
                'high_domain_entropy': 1 if len(set(domain_name.lower())) / max(len(domain_name), 1) > 0.7 else 0,
                'multiple_risk_factors': 1 if sum([
                    1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain) else 0,
                    1 if tld in ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click'] else 0,
                    1 if sum(1 for kw in ['verify', 'secure', 'suspended', 'locked', 'expired', 'urgent', 'immediate', 'confirm', 'update', 'signin'] if kw in url_lower) >= 2 else 0,
                    1 if sum(1 for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'instagram', 'twitter'] if brand in domain_name) > 0 else 0,
                    1 if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link']) else 0,
                    1 if '@' in url else 0,
                    1 if len(url) > 150 else 0,
                    1 if (len(subdomain.split('.')) if subdomain else 0) > 3 else 0
                ]) >= 3 else 0,
                'risk_factor_count': sum([
                    1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain) else 0,
                    1 if tld in ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click'] else 0,
                    1 if sum(1 for kw in ['verify', 'secure', 'suspended', 'locked', 'expired', 'urgent', 'immediate', 'confirm', 'update', 'signin'] if kw in url_lower) >= 2 else 0,
                    1 if sum(1 for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'instagram', 'twitter'] if brand in domain_name) > 0 else 0,
                    1 if any(s in domain for s in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link']) else 0,
                    1 if '@' in url else 0,
                    1 if len(url) > 150 else 0,
                    1 if (len(subdomain.split('.')) if subdomain else 0) > 3 else 0
                ])
            }
            
            return features
        except Exception as e:
            # Return safe defaults
            return {k: 0 for k in ['has_ip', 'has_https', 'suspicious_tld', 'domain_length', 'suspiciously_short_domain', 'subdomain_count', 'excessive_subdomains', 'has_hyphen_in_domain', 'high_digit_ratio', 'url_length', 'extremely_long_url', 'deep_path', 'long_query', 'critical_keyword_count', 'has_critical_keywords', 'has_brand_impersonation', 'has_financial_keywords', 'is_shortener', 'has_at_symbol', 'has_double_slash', 'special_char_density', 'high_special_char_density', 'high_domain_entropy', 'multiple_risk_factors', 'risk_factor_count']}