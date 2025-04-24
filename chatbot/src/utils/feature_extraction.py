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
    
    @staticmethod
    def _extract_content_features(url: str) -> Dict[str, Any]:
        """extract features from page content"""
        features = {}
        
        try:
            # Validate the URL to prevent SSRF
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme.startswith("http"):
                raise ValueError("Invalid URL scheme. Only HTTP and HTTPS are allowed.")
            if DeepFeatureExtractor._is_private_ip(parsed_url.hostname):
                raise ValueError("URL resolves to a private or reserved IP address.")
            
            # request with a timeout and user agent
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # check for iframes
                features["has_iframe"] = 1 if soup.find('iframe') else 0
                
                # check for JavaScript that might disable right click
                scripts = soup.find_all('script')
                script_text = ' '.join([script.string for script in scripts if script.string])
                features["disables_right_click"] = 1 if 'preventDefault' in script_text and 'contextmenu' in script_text else 0
                
                # check for popups
                features["has_popup"] = 1 if 'window.open' in script_text else 0
                
                # check for login forms
                forms = soup.find_all('form')
                has_login_form = 0
                forms_to_external = 0
                
                for form in forms:
                    # check if form has password field
                    if form.find('input', {'type': 'password'}):
                        has_login_form = 1
                        
                    # check if form submits to external domain
                    if form.get('action'):
                        form_action = form['action']
                        if form_action.startswith('http') and url not in form_action:
                            forms_to_external = 1
                
                features["has_login_form"] = has_login_form
                features["forms_to_external"] = forms_to_external
                
                # check if favicon is from the same domain
                favicon_link = soup.find('link', rel=lambda x: x and ('icon' in x.lower() or 'shortcut' in x.lower()))
                features["favicon_same_domain"] = 1  # Default to yes
                
                if favicon_link and favicon_link.get('href'):
                    favicon_url = favicon_link['href']
                    if favicon_url.startswith('http') and url not in favicon_url:
                        features["favicon_same_domain"] = 0
                
                # calculate ratio of external JavaScript files
                js_links = soup.find_all('script', src=True)
                ext_js = 0
                for js in js_links:
                    if js['src'].startswith('http') and url not in js['src']:
                        ext_js += 1
                
                features["external_js_ratio"] = ext_js / len(js_links) if js_links else 0
            else:
                # default values if page couldn't be loaded
                features["has_iframe"] = 0
                features["disables_right_click"] = 0
                features["has_popup"] = 0
                features["has_login_form"] = 0
                features["forms_to_external"] = 0
                features["external_js_ratio"] = 0
                features["favicon_same_domain"] = 1
                
        except Exception as e:
            logger.warning(f"Error fetching URL content: {e}")
            # default values if page couldn't be loaded
            features["has_iframe"] = 0
            features["disables_right_click"] = 0
            features["has_popup"] = 0
            features["has_login_form"] = 0
            features["forms_to_external"] = 0
            features["external_js_ratio"] = 0
            features["favicon_same_domain"] = 1
            
        return features
    
    @staticmethod
    def _is_private_ip(hostname: str) -> bool:
        """Check if the hostname resolves to a private or reserved IP address."""
        try:
            ip = socket.gethostbyname(hostname)
            private_ranges = [
                ("10.0.0.0", "10.255.255.255"),
                ("172.16.0.0", "172.31.255.255"),
                ("192.168.0.0", "192.168.255.255"),
                ("127.0.0.0", "127.255.255.255"),
                ("169.254.0.0", "169.254.255.255"),
                ("::1", "::1"),  # IPv6 loopback
                ("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),  # IPv6 private
            ]
            ip_addr = ipaddress.ip_address(ip)
            for start, end in private_ranges:
                if ipaddress.ip_address(start) <= ip_addr <= ipaddress.ip_address(end):
                    return True
            return False
        except Exception:
            return True  # Default to private if resolution fails
        
    @staticmethod
    def prepare_features_for_model(features, feature_list):
        """create an array with features in the correct order"""
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
            
        return np.array(feature_array).reshape(1, -1)