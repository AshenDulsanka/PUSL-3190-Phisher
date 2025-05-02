import re
import time
import socket
import numpy as np
from urllib.parse import urlparse
import tldextract
import whois
import dns.resolver
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import Levenshtein
import ssl
from typing import Dict, Any, List, Optional, Tuple
import ipaddress

from ..logging_config import get_logger

logger = get_logger(__name__)

# whitelist for legitimate HTTP URLs
HTTP_WHITELIST = ['example.com', 'info.cern.ch', 'localhost']

class FeatureExtractor:
    """service for extracting comprehensive features for deep URL analysis"""

    @staticmethod
    def is_url_safe(url):
        """check if a URL is safe to request (not pointing to internal/private network)"""
        try:
            parsed_url = urlparse(url)
            
            # make sure it's HTTP or HTTPS
            if parsed_url.scheme not in ['http', 'https']:
                logger.warning(f"Rejected URL with invalid scheme: {url}")
                return False
            
            # get the domain
            domain = parsed_url.netloc
            if ':' in domain:  # remove port if present
                domain = domain.split(':')[0]
            
            # check for valid domain format
            if not domain or '.' not in domain:
                logger.warning(f"Rejected URL with invalid domain: {url}")
                return False
                
            # check domain against whitelist (if exact match allowed)
            from ..config import HTTP_WHITELIST
            if domain in HTTP_WHITELIST:
                return True
            
            # check for dangerous internal hostnames
            dangerous_hostnames = ['localhost', '127.0.0.1', '0.0.0.0', 
                                  'internal', 'intranet', 'admin']
            if any(h in domain for h in dangerous_hostnames):
                logger.warning(f"Rejected URL with dangerous hostname: {url}")
                return False
                
            # resolve domain to IP
            try:
                ip_addresses = socket.getaddrinfo(domain, None)
            except socket.gaierror:
                logger.warning(f"Could not resolve domain: {domain}")
                return False
                
            # check if any resolved IP is private/internal
            for addr_info in ip_addresses:
                ip_str = addr_info[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast:
                        logger.warning(f"Rejected URL resolving to private/internal IP: {url} -> {ip_str}")
                        return False
                    
                    # check for specific CIDR blocks explicitly
                    forbidden_cidrs = [
                        '10.0.0.0/8',      # private network
                        '172.16.0.0/12',   # private network
                        '192.168.0.0/16',  # private network
                        '127.0.0.0/8',     # localhost
                        '169.254.0.0/16',  # link-local
                        '192.0.2.0/24',    # test-net
                        '224.0.0.0/4',     # multicast
                        '240.0.0.0/4'      # reserved
                    ]
                    
                    for cidr in forbidden_cidrs:
                        network = ipaddress.ip_network(cidr)
                        if ip in network:
                            logger.warning(f"Rejected URL with IP in forbidden CIDR: {url} -> {ip_str} in {cidr}")
                            return False
                        
                except ValueError:
                    logger.warning(f"Invalid IP address: {ip_str}")
                    return False
                    
            return True
        except Exception as e:
            logger.error(f"Error checking URL safety: {str(e)}")
            return False
    
    @staticmethod
    def extract_features(url: str) -> Dict[str, Any]:
        """
        extract all features needed for deep URL analysis for the chatbot model
        """
        try:
            start_time = time.time()
            
            features = FeatureExtractor.extract_url_features(url)
            
            # log timing for monitoring
            elapsed = time.time() - start_time
            logger.info(f"Feature extraction completed in {elapsed:.2f}s for {url[:30]}")
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features for URL {url}: {str(e)}", exc_info=True)
            # return default features in case of error
            return FeatureExtractor.get_default_features()
    
    @staticmethod
    def get_domain(url):
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            if extracted.subdomain:
                full_domain = f"{extracted.subdomain}.{domain}"
            else:
                full_domain = domain
            return domain, full_domain
        except:
            return None, None
    
    @staticmethod
    def get_domain_info(domain):
        """domain registration info using WHOIS"""
        try:
            w = whois.whois(domain)

            # get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            # get expiration date
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            # calculate age in days
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
            else:
                domain_age = -1

            # calculate registration length in days
            if creation_date and expiration_date:
                reg_len = (expiration_date - creation_date).days
            else:
                reg_len = -1

            return {
                'domain_age': domain_age,
                'registration_length': reg_len
            }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {str(e)}")
            return {
                'domain_age': -1,
                'registration_length': -1
            }
    
    @staticmethod
    def get_dns_records(domain):
        """checking if domain has proper DNS records"""
        records = {
            'has_a': False,
            'has_mx': False,
            'has_ns': False,
            'total_records': 0
        }

        try:
            # A record
            try:
                answers = dns.resolver.resolve(domain, 'A')
                records['has_a'] = len(answers) > 0
                records['total_records'] += len(answers)
            except:
                pass

            # MX record
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                records['has_mx'] = len(answers) > 0
                records['total_records'] += len(answers)
            except:
                pass

            # NS record
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                records['has_ns'] = len(answers) > 0
                records['total_records'] += len(answers)
            except:
                pass

            return records
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {str(e)}")
            return records
    
    @staticmethod
    def get_default_html_features():
        return {
            'external_favicon': False,
            'form_action_external': False,
            'external_scripts': 0,
            'external_links': 0,
            'internal_links': 1  # default to 1 to avoid division by zero
        }
    
    @staticmethod
    def analyze_html_content(url):
        try:
            # validate the URL first
            if not FeatureExtractor.is_url_safe(url):
                logger.warning(f"Skipping unsafe URL: {url}")
                return FeatureExtractor.get_default_html_features()

            # resolve the URL to ensure it does not point to private/internal IPs
            resolved_ip = FeatureExtractor.resolve_url_to_ip(url)
            if not FeatureExtractor.is_ip_safe(resolved_ip):
                logger.warning(f"Skipping URL with unsafe IP: {url} (resolved to {resolved_ip})")
                return FeatureExtractor.get_default_html_features()
            
            # ensures no redirection to internal resources
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # create a session with restrictive settings
            session = requests.Session()
            session.max_redirects = 2  # limit redirects
                
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }

            response = session.get(url, headers=headers, timeout=3, allow_redirects=False, verify=True)

            if response.status_code != 200:
                return FeatureExtractor.get_default_html_features()

            soup = BeautifulSoup(response.text, 'html.parser')
            domain, full_domain = FeatureExtractor.get_domain(url)

            # favicon analysis
            favicon = soup.find('link', rel=lambda r: r and 'icon' in r.lower())
            external_favicon = False
            if favicon and favicon.get('href'):
                favicon_url = favicon['href']
                if favicon_url.startswith('http'):
                    favicon_domain = FeatureExtractor.get_domain(favicon_url)[0]
                    external_favicon = favicon_domain != domain

            # forms analysis
            forms = soup.find_all('form')
            form_action_external = False
            for form in forms:
                action = form.get('action', '')
                if action and action.startswith('http'):
                    action_domain = FeatureExtractor.get_domain(action)[0]
                    if action_domain != domain:
                        form_action_external = True
                        break

            # script analysis
            scripts = soup.find_all('script', src=True)
            external_scripts = 0
            for script in scripts:
                if script['src'].startswith('http'):
                    script_domain = FeatureExtractor.get_domain(script['src'])[0]
                    if script_domain != domain:
                        external_scripts += 1

            # link analysis
            links = soup.find_all('a', href=True)
            external_links = 0
            internal_links = 0

            for link in links:
                href = link['href'].lower()
                if href.startswith('http'):
                    link_domain = FeatureExtractor.get_domain(href)[0]
                    if link_domain != domain:
                        external_links += 1
                    else:
                        internal_links += 1
                else:
                    internal_links += 1

            return {
                'external_favicon': external_favicon,
                'form_action_external': form_action_external,
                'external_scripts': external_scripts,
                'external_links': external_links,
                'internal_links': internal_links
            }
        except Exception as e:
            logger.debug(f"HTML analysis failed for {url}: {str(e)}")
            return FeatureExtractor.get_default_html_features()
    
    @staticmethod
    def resolve_url_to_ip(url: str) -> str:
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            return socket.gethostbyname(hostname)
        except Exception as e:
            logger.error(f"Failed to resolve URL to IP: {url}, error: {str(e)}")
            return ""

    @staticmethod
    def is_ip_safe(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback)
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

    @staticmethod
    def get_popular_brand_domains():
        return {
            # tech companies
            'google': ['google.com', 'gmail.com', 'youtube.com'],
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'aws.amazon.com'],
            'meta': ['facebook.com', 'instagram.com', 'whatsapp.com'],
            'paypal': ['paypal.com', 'paypal.me'],

            # financial
            'bank': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com'],
            'investment': ['fidelity.com', 'vanguard.com', 'schwab.com'],

            # email providers
            'mail': ['yahoo.com', 'hotmail.com', 'aol.com', 'protonmail.com'],

            # social media
            'social': ['twitter.com', 'linkedin.com', 'pinterest.com', 'reddit.com'],

            # education
            'education': ['coursera.org', 'udemy.com', 'edx.org']
        }
    
    @staticmethod
    def detect_typosquatting(domain):
        try:
            brand_domains = []
            for domains in FeatureExtractor.get_popular_brand_domains().values():
                brand_domains.extend(domains)

            result = {
                'is_typosquatting': False,
                'impersonated_domain': None,
                'edit_distance': None
            }

            if len(domain) < 4:
                return result

            domain = domain.lower()
            domain_base = domain.split('.')[0]

            # quick character substitution check
            char_subs = {'0': 'o', 'o': '0', '1': 'l', 'l': '1', 'i': '1'}

            for brand_domain in brand_domains:
                brand_base = brand_domain.split('.')[0]

                # skip if length difference is too large
                if abs(len(domain_base) - len(brand_base)) > 3:
                    continue

                # use Levenshtein distance
                try:
                    distance = Levenshtein.distance(domain_base, brand_base)
                    if len(brand_base) > 0:
                        ratio = distance / max(len(domain_base), len(brand_base))

                        # strong match if edit distance ratio is low
                        if ratio <= 0.2 and domain_base != brand_base:
                            result['is_typosquatting'] = True
                            result['impersonated_domain'] = brand_domain
                            result['edit_distance'] = distance
                            return result
                except:
                    # fallback if Levenshtein fails
                    # check for simple substitutions
                    for sub_from, sub_to in char_subs.items():
                        if sub_from in domain_base:
                            test_domain = domain_base.replace(sub_from, sub_to)
                            if test_domain == brand_base:
                                result['is_typosquatting'] = True
                                result['impersonated_domain'] = brand_domain
                                return result

            return result
        except Exception as e:
            logger.error(f"Error in typosquatting detection for domain {domain}: {str(e)}")
            return {'is_typosquatting': False, 'impersonated_domain': None, 'edit_distance': None}
    
    @staticmethod
    def detect_brand_in_subdomain(url):
        try:
            extracted = tldextract.extract(url)
            if not extracted.subdomain:
                return {'has_brand_in_subdomain': False}

            result = {
                'has_brand_in_subdomain': False,
                'impersonated_brand': None
            }

            subdomain = extracted.subdomain.lower()

            # check if subdomain contains a brand name
            for brand, domains in FeatureExtractor.get_popular_brand_domains().items():
                if brand in subdomain:
                    # check if the main domain isn't actually owned by this brand
                    if not any(d == f"{extracted.domain}.{extracted.suffix}" for d in domains):
                        result['has_brand_in_subdomain'] = True
                        result['impersonated_brand'] = brand
                        break

            return result
        except Exception as e:
            logger.error(f"Error in subdomain brand detection for URL {url}: {str(e)}")
            return {'has_brand_in_subdomain': False}
    
    @staticmethod
    def get_default_features():
        return {
            # strongest predictors
            'uses_http': 0,                
            'LegitimacyScore': 0.5,        # combined risk score
            'PrefixSuffix-': 0,            # dashes in domain

            # strong predictors
            'WebsiteTraffic': 0,           # DNS record count
            'DNSRecording': 0,             # Proper DNS setup
            'PageRank': 0,                 # DNS maturity/quality
            'GoogleIndex': 0,              # DNS indexability

            # medium predictors
            'SubDomains': 0,               # Subdomain count
            'DomainLength': 0,             # Length of domain name
            'LinksPointingToPage': 0,      # Backlink indicator
            'StatsReport': 0,              # Domain reputation

            # weaker but still useful predictors
            'DomainRegLen': 0,             # Registration length
            'RequestURL': 0,               # External script requests
            'AbnormalURL': 0,              # Suspicious terms in URL
            'Symbol@': 0,                  # @ symbol in URL

            # additional high-value features
            'IsTyposquatting': 0,          # Brand impersonation detection
            'BrandInSubdomain': 0,         # Brand impersonation in subdomain
            'UsingIP': 0,
            'AgeofDomain': 0
        }
    
    @staticmethod
    def extract_url_features(url):
        try:
            features = FeatureExtractor.get_default_features()

            # URL STRUCTURE FEATURES
            features['UsingIP'] = 1 if bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)) else 0
            features['Symbol@'] = 1 if '@' in url else 0
            features['PrefixSuffix-'] = 1 if '-' in urlparse(url).netloc else 0

            # DOMAIN FEATURES
            domain, full_domain = FeatureExtractor.get_domain(url)
            if not domain:
                return FeatureExtractor.get_default_features()

            # extract subdomain count
            extracted = tldextract.extract(url)
            features['SubDomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0

            # PROTOCOL FEATURES
            features['uses_http'] = 0 if url.startswith('https') else 1

            # length-based features
            features['DomainLength'] = 1 if len(domain) > 20 else 0

            # WHOIS INFORMATION
            whois_info = FeatureExtractor.get_domain_info(domain)
            features['DomainRegLen'] = 1 if whois_info['registration_length'] > 365 else 0
            features['AgeofDomain'] = 1 if whois_info['domain_age'] > 180 else 0

            # DNS FEATURES - critical legitimacy signals
            dns_info = FeatureExtractor.get_dns_records(domain)
            features['DNSRecording'] = 1 if dns_info['has_a'] and dns_info['has_ns'] else 0
            features['WebsiteTraffic'] = 1 if dns_info['total_records'] > 3 else 0
            features['PageRank'] = 1 if dns_info['has_a'] and dns_info['has_mx'] and dns_info['has_ns'] else 0
            features['GoogleIndex'] = 1 if dns_info['has_a'] and dns_info['has_ns'] else 0
            features['LinksPointingToPage'] = 1 if whois_info['domain_age'] > 365 else 0
            features['StatsReport'] = 1 if whois_info['domain_age'] > 180 and dns_info['total_records'] > 3 else 0

            # ADVANCED PHISHING DETECTION
            typosquatting = FeatureExtractor.detect_typosquatting(domain)
            features['IsTyposquatting'] = 1 if typosquatting['is_typosquatting'] else 0

            subdomain_analysis = FeatureExtractor.detect_brand_in_subdomain(url)
            features['BrandInSubdomain'] = 1 if subdomain_analysis['has_brand_in_subdomain'] else 0

            # check for suspicious terms in URL
            suspicious_terms = ['login', 'signin', 'verify', 'account', 'security', 'update', 'confirm', 'payment']
            features['AbnormalURL'] = 1 if any(term in url.lower() for term in suspicious_terms) else 0

            # HTML CONTENT ANALYSIS
            if url.startswith('http'):
                try:
                    html_info = FeatureExtractor.analyze_html_content(url)
                    features['RequestURL'] = 1 if html_info['external_scripts'] > 0 else 0
                except Exception as e:
                    logger.debug(f"HTML analysis error: {str(e)}")

            # LEGITIMACY SCORE CALCULATION
            legitimacy_score = 0.5  # start neutral

            # domain age increases legitimacy
            if features['AgeofDomain'] == 1:
                legitimacy_score += 0.2

            # DNS setup increases legitimacy
            if features['DNSRecording'] == 1 and features['PageRank'] == 1:
                legitimacy_score += 0.1

            # HTTP protocol reduces legitimacy (except for whitelist)
            if features['uses_http'] == 1:
                if any(domain.endswith(white_domain) for white_domain in HTTP_WHITELIST):
                    pass  # no penalty for whitelisted sites
                else:
                    legitimacy_score -= 0.2

            # phishing signals dramatically reduce legitimacy
            if features['IsTyposquatting'] == 1:
                legitimacy_score -= 0.3
            if features['BrandInSubdomain'] == 1:
                legitimacy_score -= 0.3

            features['LegitimacyScore'] = max(0, min(1, legitimacy_score))

            # handle special whitelisted cases
            if features['uses_http'] == 1 and any(domain.endswith(white) for white in HTTP_WHITELIST):
                features['LegitimacyScore'] = 0.8

            return features
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return FeatureExtractor.get_default_features()
    
    @staticmethod
    def prepare_features_for_model(features: Dict[str, Any], feature_list: List[str]) -> np.ndarray:
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
            
        return np.array(feature_array).reshape(1, -1)