import re
import time
import socket
import numpy as np
import math
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
                'registration_length': reg_len,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'registrar': getattr(w, 'registrar', None),
                'name_servers': getattr(w, 'name_servers', [])
            }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {str(e)}")
            return {
                'domain_age': -1,
                'registration_length': -1,
                'creation_date': None,
                'expiration_date': None,
                'registrar': None,
                'name_servers': []
            }
    
    @staticmethod
    def get_dns_records(domain):
        """checking if domain has proper DNS records"""
        records = {
            'has_a': False,
            'has_mx': False,
            'has_ns': False,
            'has_txt': False,
            'has_cname': False,
            'total_records': 0,
            'mx_count': 0,
            'ns_count': 0,
            'a_count': 0
        }

        try:
            # a record
            try:
                answers = dns.resolver.resolve(domain, 'A')
                records['has_a'] = len(answers) > 0
                records['a_count'] = len(answers)
                records['total_records'] += len(answers)
            except:
                pass

            # mx record
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                records['has_mx'] = len(answers) > 0
                records['mx_count'] = len(answers)
                records['total_records'] += len(answers)
            except:
                pass

            # ns record
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                records['has_ns'] = len(answers) > 0
                records['ns_count'] = len(answers)
                records['total_records'] += len(answers)
            except:
                pass

            # txt record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                records['has_txt'] = len(answers) > 0
                records['total_records'] += len(answers)
            except:
                pass

            # cname record
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                records['has_cname'] = len(answers) > 0
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
            'internal_links': 1,  # default to 1 to avoid division by zero
            'iframe_count': 0,
            'form_count': 0,
            'input_count': 0,
            'hidden_inputs': 0,
            'suspicious_forms': 0,
            'external_css': 0,
            'meta_refresh': False,
            'popup_windows': 0,
            'onload_events': 0
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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }

            response = session.get(url, headers=headers, timeout=3, allow_redirects=False, verify=False)

            if response.status_code != 200:
                return FeatureExtractor.get_default_html_features()

            soup = BeautifulSoup(response.text, 'html.parser')
            domain, full_domain = FeatureExtractor.get_domain(url)

            features = FeatureExtractor.get_default_html_features()

            # favicon analysis
            favicon = soup.find('link', rel=lambda r: r and 'icon' in r.lower())
            if favicon and favicon.get('href'):
                favicon_url = favicon['href']
                if favicon_url.startswith('http'):
                    favicon_domain = FeatureExtractor.get_domain(favicon_url)[0]
                    features['external_favicon'] = favicon_domain != domain

            # forms analysis
            forms = soup.find_all('form')
            features['form_count'] = len(forms)

            for form in forms:
                action = form.get('action', '')
                if action and action.startswith('http'):
                    action_domain = FeatureExtractor.get_domain(action)[0]
                    if action_domain != domain:
                        features['form_action_external'] = True
                        features['suspicious_forms'] += 1

            # input analysis
            inputs = soup.find_all('input')
            features['input_count'] = len(inputs)
            features['hidden_inputs'] = len([inp for inp in inputs if inp.get('type') == 'hidden'])

            # script analysis
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                if script['src'].startswith('http'):
                    script_domain = FeatureExtractor.get_domain(script['src'])[0]
                    if script_domain != domain:
                        features['external_scripts'] += 1

            # css analysis
            css_links = soup.find_all('link', rel='stylesheet')
            for css in css_links:
                href = css.get('href', '')
                if href.startswith('http'):
                    css_domain = FeatureExtractor.get_domain(href)[0]
                    if css_domain != domain:
                        features['external_css'] += 1

            # link analysis
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href'].lower()
                if href.startswith('http'):
                    link_domain = FeatureExtractor.get_domain(href)[0]
                    if link_domain != domain:
                        features['external_links'] += 1
                    else:
                        features['internal_links'] += 1
                else:
                    features['internal_links'] += 1

            # iframe analysis
            iframes = soup.find_all('iframe')
            features['iframe_count'] = len(iframes)

            # meta refresh detection
            meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
            features['meta_refresh'] = bool(meta_refresh)

            # javascript event analysis
            features['onload_events'] = len(soup.find_all(attrs={'onload': True}))
            features['popup_windows'] = len(re.findall(r'window\.open|popup', response.text, re.IGNORECASE))

            return features

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
    def get_comprehensive_brand_domains():
        """comprehensive brand domain database for advanced detection"""
        return {
            # tech giants
            'google': ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com', 'googledrive.com'],
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com', 'msn.com'],
            'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
            'amazon': ['amazon.com', 'aws.amazon.com', 'amazonworkspaces.com', 'amazoncognito.com'],
            'meta': ['facebook.com', 'instagram.com', 'whatsapp.com', 'fb.com'],

            # financial institutions
            'paypal': ['paypal.com', 'paypal.me', 'paypalobjects.com'],
            'stripe': ['stripe.com', 'stripe.network'],
            'chase': ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'],
            'bankofamerica': ['bankofamerica.com', 'bofa.com', 'merrilledge.com'],
            'wellsfargo': ['wellsfargo.com', 'wf.com'],
            'citibank': ['citibank.com', 'citi.com', 'citicards.com'],

            # cryptocurrency
            'coinbase': ['coinbase.com', 'coinbase.pro'],
            'binance': ['binance.com', 'binance.us'],
            'kraken': ['kraken.com', 'pro.kraken.com'],
            'gemini': ['gemini.com'],

            # email providers
            'yahoo': ['yahoo.com', 'ymail.com', 'rocketmail.com'],
            'protonmail': ['protonmail.com', 'proton.me'],
            'tutanota': ['tutanota.com'],

            # social media
            'twitter': ['twitter.com', 'x.com', 't.co'],
            'linkedin': ['linkedin.com'],
            'discord': ['discord.com', 'discordapp.com'],
            'telegram': ['telegram.org', 't.me'],

            # cloud services
            'dropbox': ['dropbox.com', 'getdropbox.com'],
            'onedrive': ['onedrive.com', 'onedrive.live.com'],
            'gdrive': ['drive.google.com'],

            # government & official
            'irs': ['irs.gov'],
            'ssa': ['ssa.gov'],
            'usps': ['usps.com', 'usps.gov']
        }
    
    @staticmethod
    def detect_advanced_typosquatting(domain):
        """advanced typosquatting detection with multiple techniques"""
        try:
            brand_domains = []
            for domains in FeatureExtractor.get_comprehensive_brand_domains().values():
                brand_domains.extend(domains)

            result = {
                'is_typosquatting': False,
                'impersonated_domain': None,
                'edit_distance': None,
                'attack_type': None,
                'confidence': 0.0
            }

            if len(domain) < 4:
                return result

            domain = domain.lower()
            domain_base = domain.split('.')[0]

            # advanced character substitution patterns
            advanced_substitutions = {
                '0': ['o', 'O'],
                'o': ['0'],
                '1': ['l', 'I', 'i'],
                'l': ['1', 'I', 'i'],
                'i': ['1', 'l'],
                'I': ['1', 'l', 'i'],
                '5': ['s', 'S'],
                's': ['5', '$'],
                'e': ['3'],
                'a': ['@'],
                'g': ['q'],
                'n': ['m'],
                'rn': ['m'],
                'cl': ['d'],
                'vv': ['w']
            }

            for brand_domain in brand_domains:
                brand_base = brand_domain.split('.')[0]

                # skip if length difference is too large
                if abs(len(domain_base) - len(brand_base)) > 4:
                    continue

                # 1. levenshtein distance check
                try:
                    distance = Levenshtein.distance(domain_base, brand_base)
                    if len(brand_base) > 0:
                        ratio = distance / max(len(domain_base), len(brand_base))

                        if ratio <= 0.25 and domain_base != brand_base:
                            confidence = 1.0 - ratio
                            if confidence > result['confidence']:
                                result.update({
                                    'is_typosquatting': True,
                                    'impersonated_domain': brand_domain,
                                    'edit_distance': distance,
                                    'attack_type': 'character_substitution',
                                    'confidence': confidence
                                })
                except:
                    pass

                # 2. advanced substitution check
                for sub_from, sub_to_list in advanced_substitutions.items():
                    for sub_to in sub_to_list:
                        if sub_from in domain_base:
                            test_domain = domain_base.replace(sub_from, sub_to)
                            if test_domain == brand_base:
                                result.update({
                                    'is_typosquatting': True,
                                    'impersonated_domain': brand_domain,
                                    'attack_type': 'character_substitution',
                                    'confidence': 0.9
                                })
                                return result

                # 3. insertion/deletion attack
                if len(domain_base) == len(brand_base) + 1:
                    # check character insertion
                    for i in range(len(domain_base)):
                        test_domain = domain_base[:i] + domain_base[i+1:]
                        if test_domain == brand_base:
                            result.update({
                                'is_typosquatting': True,
                                'impersonated_domain': brand_domain,
                                'attack_type': 'character_insertion',
                                'confidence': 0.85
                            })
                            return result

            return result

        except Exception as e:
            logger.error(f"Advanced typosquatting detection failed: {str(e)}")
            return {'is_typosquatting': False, 'impersonated_domain': None, 'edit_distance': None, 'attack_type': None, 'confidence': 0.0}
    
    @staticmethod
    def detect_brand_in_subdomain(url):
        """detect brand names in subdomains with advanced pattern matching"""
        try:
            extracted = tldextract.extract(url)
            if not extracted.subdomain:
                return {'has_brand_in_subdomain': False, 'impersonated_brand': None}

            result = {
                'has_brand_in_subdomain': False,
                'impersonated_brand': None
            }

            subdomain = extracted.subdomain.lower()
            main_domain = f"{extracted.domain}.{extracted.suffix}".lower()

            # check if subdomain contains a brand name
            for brand, domains in FeatureExtractor.get_comprehensive_brand_domains().items():
                # Look for brand name in subdomain
                if brand in subdomain:
                    # verify this isn't actually a legitimate subdomain of the brand
                    is_legitimate = any(main_domain == d.lower() for d in domains)

                    if not is_legitimate:
                        result['has_brand_in_subdomain'] = True
                        result['impersonated_brand'] = brand
                        break

            return result
        except Exception as e:
            logger.debug(f"Error in subdomain brand detection: {str(e)}")
            return {'has_brand_in_subdomain': False, 'impersonated_brand': None}
    
    @staticmethod
    def get_default_features():
        return {
            # original chatbot features
            'uses_http': 0,
            'LegitimacyScore': 0.5,
            'PrefixSuffix-': 0,
            'WebsiteTraffic': 0,
            'DNSRecording': 0,
            'PageRank': 0,
            'GoogleIndex': 0,
            'SubDomains': 0,
            'DomainLength': 0,
            'LinksPointingToPage': 0,
            'StatsReport': 0,
            'DomainRegLen': 0,
            'RequestURL': 0,
            'AbnormalURL': 0,
            'Symbol@': 0,
            'IsTyposquatting': 0,
            'BrandInSubdomain': 0,
            'UsingIP': 0,
            'AgeofDomain': 0,

            # enhanced ultra-high recall features
            'has_ip': 0,
            'has_https': 0,
            'suspicious_tld': 0,
            'domain_length': 0,
            'subdomain_count': 0,
            'excessive_subdomains': 0,
            'ultra_excessive_subdomains': 0,
            'has_hyphen_in_domain': 0,
            'multiple_hyphens': 0,
            'high_digit_ratio': 0,
            'high_domain_entropy': 0,
            'url_length': 0,
            'extremely_long_url': 0,
            'suspicious_url_length': 0,
            'deep_path': 0,
            'long_query': 0,
            'path_length': 0,
            'query_length': 0,
            'keyword_count': 0,
            'has_phishing_keywords': 0,
            'multiple_phishing_keywords': 0,
            'has_brand_impersonation': 0,
            'has_suspicious_domain_pattern': 0,
            'is_shortener': 0,
            'has_at_symbol': 0,
            'has_double_slash': 0,
            'special_char_density': 0,
            'high_special_char_density': 0,
            'homograph_risk': 0,
            'potential_typosquatting': 0,
            'risk_factor_count': 0,
            'multiple_critical_risks': 0,
            'ultra_high_risk': 0
        }
    
    @staticmethod
    def extract_url_features(url):
        """extract comprehensive features for chatbot deep analysis (50+ features)"""
        try:
            features = FeatureExtractor.get_default_features()

            # basic url structure
            features['UsingIP'] = 1 if bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url)) else 0
            features['Symbol@'] = 1 if '@' in url else 0
            features['PrefixSuffix-'] = 1 if '-' in urlparse(url).netloc else 0
            features['has_ip'] = features['UsingIP']  # Compatibility
            features['has_at_symbol'] = features['Symbol@']  # Compatibility

            # domain analysis
            domain, full_domain = FeatureExtractor.get_domain(url)
            if not domain:
                return FeatureExtractor.get_default_features()

            extracted = tldextract.extract(url)
            subdomain_parts = extracted.subdomain.split('.') if extracted.subdomain else []
            features['SubDomains'] = len(subdomain_parts)
            features['subdomain_count'] = features['SubDomains']  # Compatibility

            # enhanced subdomain analysis
            features['excessive_subdomains'] = 1 if len(subdomain_parts) > 2 else 0
            features['ultra_excessive_subdomains'] = 1 if len(subdomain_parts) > 4 else 0

            # protocol & security
            features['uses_http'] = 0 if url.startswith('https') else 1
            features['has_https'] = 1 if url.startswith('https') else 0

            # domain characteristics
            features['DomainLength'] = len(extracted.domain) if extracted.domain else 0
            features['domain_length'] = features['DomainLength']  # Compatibility

            # enhanced domain analysis
            domain_name = extracted.domain or ''
            features['has_hyphen_in_domain'] = 1 if '-' in domain_name else 0
            features['multiple_hyphens'] = 1 if domain_name.count('-') > 1 else 0

            digit_ratio = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)
            features['high_digit_ratio'] = 1 if digit_ratio > 0.2 else 0

            # tld analysis
            ultra_suspicious_tlds = [
                'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'download',
                'link', 'info', 'biz', 'xyz', 'club', 'online', 'site',
                'website', 'space', 'tech', 'store', 'shop', 'win', 'vip',
                'icu', 'rest', 'cc', 'sbs', 'world', 'support'
            ]
            features['suspicious_tld'] = 1 if extracted.suffix in ultra_suspicious_tlds else 0

            # url structure analysis
            features['url_length'] = len(url)
            features['extremely_long_url'] = 1 if len(url) > 100 else 0
            features['suspicious_url_length'] = 1 if len(url) > 75 else 0

            path_parts = urlparse(url).path.split('/')
            features['deep_path'] = 1 if len(path_parts) > 4 else 0
            features['path_length'] = len(urlparse(url).path)

            query = urlparse(url).query
            features['query_length'] = len(query)
            features['long_query'] = 1 if len(query) > 30 else 0

            # whois information
            whois_info = FeatureExtractor.get_domain_info(domain)
            features['DomainRegLen'] = 1 if whois_info['registration_length'] > 365 else 0
            features['AgeofDomain'] = 1 if whois_info['domain_age'] > 180 else 0

            # dns features 
            dns_info = FeatureExtractor.get_dns_records(domain)
            features['DNSRecording'] = 1 if dns_info['has_a'] and dns_info['has_ns'] else 0
            features['WebsiteTraffic'] = 1 if dns_info['total_records'] > 3 else 0
            features['PageRank'] = 1 if dns_info['has_a'] and dns_info['has_mx'] and dns_info['has_ns'] else 0
            features['GoogleIndex'] = 1 if dns_info['has_a'] and dns_info['has_ns'] else 0
            features['LinksPointingToPage'] = 1 if whois_info['domain_age'] > 365 else 0
            features['StatsReport'] = 1 if whois_info['domain_age'] > 180 and dns_info['total_records'] > 3 else 0

            # phishing keywords 
            ultra_phishing_keywords = [
                'verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm',
                'suspended', 'locked', 'expired', 'urgent', 'immediate', 'security',
                'alert', 'warning', 'action', 'required', 'validation', 'authenticate',
                'verification', 'restore', 'unlock', 'resolve', 'customer',
                'banking', 'payment', 'billing', 'invoice', 'transaction', 'refund',
                'card', 'credit', 'debit', 'wallet', 'paypal', 'stripe',
                'support', 'service', 'center', 'portal', 'help', 'notification'
            ]

            keyword_count = sum(1 for kw in ultra_phishing_keywords if kw in url.lower())
            features['keyword_count'] = keyword_count
            features['has_phishing_keywords'] = 1 if keyword_count >= 1 else 0
            features['multiple_phishing_keywords'] = 1 if keyword_count >= 2 else 0

            # brand impersonation 
            major_brands = [
                'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta',
                'instagram', 'twitter', 'linkedin', 'youtube', 'netflix', 'spotify',
                'adobe', 'zoom', 'dropbox', 'gmail', 'outlook', 'icloud',
                'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover',
                'chase', 'wells', 'bofa', 'citi', 'usbank', 'hsbc', 'td',
                'bankofamerica', 'wellsfargo', 'citibank', 'pnc', 'capitalone',
                'bank', 'credit', 'union', 'financial', 'banking'
            ]

            brand_count = sum(1 for brand in major_brands if brand in domain_name)
            features['has_brand_impersonation'] = 1 if brand_count > 0 else 0

            # typosquatting detection 
            typosquatting = FeatureExtractor.detect_advanced_typosquatting(domain)
            features['IsTyposquatting'] = 1 if typosquatting['is_typosquatting'] else 0

            # subdomain brand analysis 
            subdomain_analysis = FeatureExtractor.detect_brand_in_subdomain(url)
            features['BrandInSubdomain'] = 1 if subdomain_analysis['has_brand_in_subdomain'] else 0

            # suspicious domain patterns
            suspicious_domain_patterns = [
                'verification', 'security', 'account', 'update', 'confirm',
                'locked', 'suspended', 'expired', 'urgent', 'immediate',
                'customer', 'support', 'service', 'center', 'portal'
            ]
            domain_pattern_count = sum(1 for pattern in suspicious_domain_patterns if pattern in domain_name)
            features['has_suspicious_domain_pattern'] = 1 if domain_pattern_count > 0 else 0

            # url shotner detection
            shorteners = [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
                'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy',
                'cutt.ly', 'bitly.com', 'short.io', 'rebrand.ly'
            ]
            features['is_shortener'] = 1 if any(s in domain for s in shorteners) else 0

            # suspicious characters
            features['has_double_slash'] = 1 if '//' in url[8:] else 0

            special_char_count = len(re.findall(r'[%\-_=&\?]', url))
            features['special_char_density'] = special_char_count / len(url) if len(url) > 0 else 0
            features['high_special_char_density'] = 1 if features['special_char_density'] > 0.1 else 0

            # advanced detection
            # entropy analysis
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
            features['high_domain_entropy'] = 1 if domain_entropy > 3.0 else 0

            # homograph detection
            features['homograph_risk'] = 1 if any(ord(c) > 127 for c in domain_name) else 0

            # advanced typosquatting patterns
            typosquatting_indicators = [
                domain_name.count('0') > 0 and 'o' in domain_name,
                domain_name.count('1') > 0 and 'l' in domain_name,
                domain_name.count('5') > 0 and 's' in domain_name,
            ]
            features['potential_typosquatting'] = 1 if any(typosquatting_indicators) else 0

            # html content analysis
            features['RequestURL'] = 0  # default
            if url.startswith('http'):
                try:
                    html_info = FeatureExtractor.analyze_html_content(url)
                    features['RequestURL'] = 1 if html_info['external_scripts'] > 0 else 0
                except Exception as e:
                    logger.debug(f"HTML analysis error for {url}: {str(e)}")

            # combined risk indicators
            critical_risk_factors = [
                features['UsingIP'],
                features['suspicious_tld'],
                features['has_brand_impersonation'],
                features['is_shortener'],
                features['multiple_phishing_keywords'],
                features['excessive_subdomains'],
                features['has_suspicious_domain_pattern']
            ]

            features['risk_factor_count'] = sum(critical_risk_factors)
            features['multiple_critical_risks'] = 1 if features['risk_factor_count'] >= 2 else 0
            features['ultra_high_risk'] = 1 if features['risk_factor_count'] >= 3 else 0

            # legacy compatibility
            features['AbnormalURL'] = features['has_phishing_keywords']

            # legitimacy score calculation
            legitimacy_score = 0.5  # start neutral

            # positive indicators
            if features['AgeofDomain'] == 1:
                legitimacy_score += 0.15
            if features['DNSRecording'] == 1 and features['PageRank'] == 1:
                legitimacy_score += 0.15
            if features['has_https'] == 1:
                legitimacy_score += 0.1
            if features['DomainRegLen'] == 1:
                legitimacy_score += 0.1

            # negative indicators
            if features['uses_http'] == 1:
                if any(domain.endswith(white_domain) for white_domain in HTTP_WHITELIST):
                    pass  # no penalty for whitelisted sites
                else:
                    legitimacy_score -= 0.2

            if features['IsTyposquatting'] == 1:
                legitimacy_score -= 0.4
            if features['BrandInSubdomain'] == 1:
                legitimacy_score -= 0.3
            if features['ultra_high_risk'] == 1:
                legitimacy_score -= 0.5

            features['LegitimacyScore'] = max(0, min(1, legitimacy_score))

            # handle special whitelisted cases
            if features['uses_http'] == 1 and any(domain.endswith(white) for white in HTTP_WHITELIST):
                features['LegitimacyScore'] = 0.8

            return features

        except Exception as e:
            logger.error(f"Error extracting features from {url}: {str(e)}")
            return FeatureExtractor.get_default_features()
    
    @staticmethod
    def prepare_features_for_model(features: Dict[str, Any], feature_list: List[str]) -> np.ndarray:
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
            
        return np.array(feature_array).reshape(1, -1)