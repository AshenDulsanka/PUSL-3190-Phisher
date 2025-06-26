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
        """Extract ultra-high recall features (33 features) optimized for ZERO false negatives"""
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
            
            # === ULTRA-SENSITIVE PHISHING DETECTION (33 FEATURES) ===
            
            # 1. CRITICAL SECURITY INDICATORS
            has_ip = 1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain) else 0
            has_https = 1 if url.startswith('https') else 0
            
            # 2. SUSPICIOUS TLD (EXPANDED LIST)
            ultra_suspicious_tlds = [
                'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'download',
                'link', 'info', 'biz', 'xyz', 'club', 'online', 'site',
                'website', 'space', 'tech', 'store', 'shop', 'win', 'vip',
                'icu', 'rest', 'cc', 'sbs', 'world', 'support'
            ]
            suspicious_tld = 1 if tld in ultra_suspicious_tlds else 0
            
            # 3. DOMAIN ANALYSIS
            domain_length = len(domain_name)
            subdomain_count = len(subdomain.split('.')) if subdomain else 0
            excessive_subdomains = 1 if subdomain_count > 2 else 0  # More sensitive
            ultra_excessive_subdomains = 1 if subdomain_count > 4 else 0
            has_hyphen_in_domain = 1 if '-' in domain_name else 0
            multiple_hyphens = 1 if domain_name.count('-') > 1 else 0
            digit_ratio = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)
            high_digit_ratio = 1 if digit_ratio > 0.2 else 0  # More sensitive
            
            # 4. URL STRUCTURE ANALYSIS
            url_length = len(url)
            path_length = len(path)
            query_length = len(query)
            extremely_long_url = 1 if url_length > 100 else 0  # More sensitive
            suspicious_url_length = 1 if url_length > 75 else 0
            deep_path = 1 if path.count('/') > 3 else 0  # More sensitive
            long_query = 1 if query_length > 30 else 0  # More sensitive
            
            # 5. PHISHING KEYWORDS (ULTRA-COMPREHENSIVE)
            ultra_phishing_keywords = [
                # Authentication & Security (CRITICAL)
                'verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm',
                'suspended', 'locked', 'expired', 'urgent', 'immediate', 'security',
                'alert', 'warning', 'action', 'required', 'validation', 'authenticate',
                'verification', 'restore', 'unlock', 'resolve', 'customer',
                # Financial (HIGH RISK)
                'banking', 'payment', 'billing', 'invoice', 'transaction', 'refund',
                'card', 'credit', 'debit', 'wallet', 'paypal', 'stripe', 'billing',
                # Brand Impersonation Patterns
                'support', 'service', 'center', 'portal', 'help', 'notification'
            ]
            
            keyword_count = sum(1 for kw in ultra_phishing_keywords if kw in url_lower)
            has_phishing_keywords = 1 if keyword_count >= 1 else 0  # More sensitive
            multiple_phishing_keywords = 1 if keyword_count >= 2 else 0
            
            # 6. BRAND IMPERSONATION (ULTRA-COMPREHENSIVE)
            major_brands = [
                # Tech Giants
                'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta',
                'instagram', 'twitter', 'linkedin', 'youtube', 'netflix', 'spotify',
                'adobe', 'zoom', 'dropbox', 'gmail', 'outlook', 'icloud',
                # Financial Institutions (CRITICAL)
                'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover',
                'chase', 'wells', 'bofa', 'citi', 'usbank', 'hsbc', 'td',
                'bankofamerica', 'wellsfargo', 'citibank', 'pnc', 'capitalone',
                'bank', 'credit', 'union', 'financial', 'banking'
            ]
            
            brand_count = sum(1 for brand in major_brands if brand in domain_name)
            has_brand_impersonation = 1 if brand_count > 0 else 0
            
            # 7. SUSPICIOUS DOMAIN PATTERNS
            suspicious_domain_patterns = [
                'verification', 'security', 'account', 'update', 'confirm',
                'locked', 'suspended', 'expired', 'urgent', 'immediate',
                'customer', 'support', 'service', 'center', 'portal'
            ]
            domain_pattern_count = sum(1 for pattern in suspicious_domain_patterns if pattern in domain_name)
            has_suspicious_domain_pattern = 1 if domain_pattern_count > 0 else 0
            
            # 8. URL SHORTENER DETECTION (EXPANDED)
            shorteners = [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
                'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy',
                'cutt.ly', 'bitly.com', 'short.io', 'rebrand.ly', 'tinylink',
                'shorturl', 'tiny', 'short'
            ]
            is_shortener = 1 if any(s in domain for s in shorteners) else 0
            
            # 9. SUSPICIOUS CHARACTERS & PATTERNS
            has_at_symbol = 1 if '@' in url else 0
            has_double_slash = 1 if '//' in url[8:] else 0
            
            # Character analysis
            special_char_count = len(re.findall(r'[%\-_=&\?]', url))
            special_char_density = special_char_count / len(url) if len(url) > 0 else 0
            high_special_char_density = 1 if special_char_density > 0.1 else 0  # More sensitive
            
            # 10. ADVANCED DETECTION
            # Homograph detection
            suspicious_chars = sum(1 for c in domain_name if ord(c) > 127)
            homograph_risk = 1 if suspicious_chars > 0 else 0
            
            # Typosquatting patterns
            typosquatting_indicators = [
                domain_name.count('0') > 0 and 'o' in domain_name,  # 0 vs O
                domain_name.count('1') > 0 and 'l' in domain_name,  # 1 vs l
                domain_name.count('5') > 0 and 's' in domain_name,  # 5 vs S
            ]
            potential_typosquatting = 1 if any(typosquatting_indicators) else 0
            
            # 11. ENTROPY ANALYSIS
            def calculate_entropy(text):
                if not text:
                    return 0
                char_counts = {}
                for char in text.lower():
                    char_counts[char] = char_counts.get(char, 0) + 1
                
                length = len(text)
                entropy = 0
                for count in char_counts.values():
                    if count > 0:
                        p = count / length
                        entropy -= p * math.log2(p)
                return entropy
            
            domain_entropy = calculate_entropy(domain_name)
            high_domain_entropy = 1 if domain_entropy > 3.0 else 0  # More sensitive
            
            # 12. COMBINED ULTRA-HIGH RISK INDICATORS
            critical_risk_factors = [
                has_ip,
                suspicious_tld,
                has_brand_impersonation,
                is_shortener,
                multiple_phishing_keywords,
                excessive_subdomains,
                has_suspicious_domain_pattern
            ]
            
            risk_factor_count = sum(critical_risk_factors)
            multiple_critical_risks = 1 if risk_factor_count >= 2 else 0  # Very sensitive
            ultra_high_risk = 1 if risk_factor_count >= 3 else 0
            
            # Return all 33 features in exact order as training
            features = {
                # Critical indicators
                'has_ip': has_ip,
                'has_https': has_https,
                'suspicious_tld': suspicious_tld,
                
                # Domain analysis
                'domain_length': domain_length,
                'subdomain_count': subdomain_count,
                'excessive_subdomains': excessive_subdomains,
                'ultra_excessive_subdomains': ultra_excessive_subdomains,
                'has_hyphen_in_domain': has_hyphen_in_domain,
                'multiple_hyphens': multiple_hyphens,
                'high_digit_ratio': high_digit_ratio,
                'high_domain_entropy': high_domain_entropy,
                
                # URL structure
                'url_length': url_length,
                'extremely_long_url': extremely_long_url,
                'suspicious_url_length': suspicious_url_length,
                'deep_path': deep_path,
                'long_query': long_query,
                'path_length': path_length,
                'query_length': query_length,
                
                # Content analysis
                'keyword_count': keyword_count,
                'has_phishing_keywords': has_phishing_keywords,
                'multiple_phishing_keywords': multiple_phishing_keywords,
                'has_brand_impersonation': has_brand_impersonation,
                'has_suspicious_domain_pattern': has_suspicious_domain_pattern,
                
                # Suspicious patterns
                'is_shortener': is_shortener,
                'has_at_symbol': has_at_symbol,
                'has_double_slash': has_double_slash,
                'special_char_density': special_char_density,
                'high_special_char_density': high_special_char_density,
                
                # Advanced detection
                'homograph_risk': homograph_risk,
                'potential_typosquatting': potential_typosquatting,
                
                # Combined risk indicators
                'risk_factor_count': risk_factor_count,
                'multiple_critical_risks': multiple_critical_risks,
                'ultra_high_risk': ultra_high_risk
            }
            
            logger.info(f"Extracted {len(features)} features for URL: {url[:50]}...")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {url}: {str(e)}")
            # Return safe defaults for all 33 features
            return {k: 0 for k in [
                'has_ip', 'has_https', 'suspicious_tld', 'domain_length',
                'subdomain_count', 'excessive_subdomains', 'ultra_excessive_subdomains',
                'has_hyphen_in_domain', 'multiple_hyphens', 'high_digit_ratio', 'high_domain_entropy',
                'url_length', 'extremely_long_url', 'suspicious_url_length', 'deep_path', 'long_query',
                'path_length', 'query_length', 'keyword_count', 'has_phishing_keywords',
                'multiple_phishing_keywords', 'has_brand_impersonation', 'has_suspicious_domain_pattern',
                'is_shortener', 'has_at_symbol', 'has_double_slash', 'special_char_density',
                'high_special_char_density', 'homograph_risk', 'potential_typosquatting',
                'risk_factor_count', 'multiple_critical_risks', 'ultra_high_risk'
            ]}
        
    @staticmethod
    def prepare_features_for_model(features, feature_list):
        # create an array with features in the correct order
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
            
        return np.array(feature_array).reshape(1, -1)