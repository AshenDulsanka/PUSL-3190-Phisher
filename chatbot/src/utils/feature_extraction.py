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
import dns.resolver
from ..logging_config import get_logger

logger = get_logger(__name__)

class DeepFeatureExtractor:
    """
    class for extracting comprehensive features from URLs for deep phishing analysis
    feature naming matches the trained model's expectations
    """
    
    @staticmethod
    def extract_features(url: str) -> Dict[str, Any]:
        """
        extract all features for a single URL according to model requirements
        """
        # basic URL features
        features = {}
        
        try:
            # check if URL uses IP address
            features['UsingIP'] = 1 if bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)) else 0
            
            # URL length
            features['LongURL'] = 1 if len(url) > 75 else 0
            
            # check for URL shortening services
            url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly', 'tiny.cc', 'shorte.st']
            features['ShortURL'] = 1 if any(shortener in url for shortener in url_shorteners) else 0
            
            # check for @ symbol
            features['Symbol@'] = 1 if '@' in url else 0
            
            # check for multiple forward slashes
            features['Redirecting//'] = 1 if url.replace('https://', '').replace('http://', '').find('//') != -1 else 0
            
            # extract domain information
            domain, full_domain = DeepFeatureExtractor._get_domain(url)
            
            if not domain:
                # if domain extraction failed, return basic features with default values
                logger.warning(f"Failed to extract domain from URL: {url}")
                return DeepFeatureExtractor._get_default_features()
            
            # check for hyphen in domain
            features['PrefixSuffix-'] = 1 if '-' in domain else 0
            
            # count subdomains
            extracted = tldextract.extract(url)
            features['SubDomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            # check if URL uses HTTPS
            features['HTTPS'] = 1 if url.startswith('https') else 0
            
            # get WHOIS information
            whois_info = DeepFeatureExtractor._get_domain_info(domain)
            features['DomainRegLen'] = 1 if whois_info['registration_length'] > 365 else 0
            features['AgeofDomain'] = 1 if whois_info['domain_age'] > 180 else 0
            
            # check for non-standard port
            parsed_url = urllib.parse.urlparse(url)
            port = parsed_url.port
            features['NonStdPort'] = 1 if port and port not in [80, 443] else 0
            
            # check if 'https' appears in domain part
            features['HTTPSDomainURL'] = 1 if 'https' in domain or 'http' in domain else 0
            
            # check for suspicious terms in URL
            suspicious_terms = ['login', 'signin', 'verify', 'account', 'security', 'update', 'confirm', 'payment']
            features['AbnormalURL'] = 1 if any(term in url.lower() for term in suspicious_terms) else 0
            
            # check for email-related terms
            features['InfoEmail'] = 1 if any(term in url.lower() for term in ['mail', 'email', 'contact']) else 0
            
            # get DNS Records
            dns_info = DeepFeatureExtractor._get_dns_records(domain)
            features['DNSRecording'] = 1 if dns_info['has_a'] and dns_info['has_ns'] else 0
            
            # website popularity estimation (based on DNS records as a proxy)
            features['WebsiteTraffic'] = 1 if dns_info['total_records'] > 3 else 0
            features['PageRank'] = 1 if dns_info['has_a'] and dns_info['has_mx'] and dns_info['has_ns'] else 0
            features['GoogleIndex'] = 1 if dns_info['has_a'] and dns_info['has_ns'] else 0
            
            # links pointing to the page (estimate based on domain age)
            features['LinksPointingToPage'] = 1 if whois_info['domain_age'] > 365 else 0
            
            # stats report availability (estimate based on domain age and DNS)
            features['StatsReport'] = 1 if whois_info['domain_age'] > 180 and dns_info['total_records'] > 3 else 0
            
            # HTML content analysis (only attempt for HTTP/HTTPS URLs)
            if url.startswith('http'):
                try:
                    html_info = DeepFeatureExtractor._analyze_html_content(url, domain)
                    
                    # favicon from different domain
                    features['Favicon'] = 1 if html_info['external_favicon'] else 0
                    
                    # external request URLs
                    features['RequestURL'] = 1 if html_info['external_scripts'] > 0 else 0
                    
                    # external anchor URLs
                    features['AnchorURL'] = 1 if html_info['external_links'] > html_info['internal_links'] else 0
                    
                    # links in script tags
                    features['LinksInScriptTags'] = 1 if html_info['external_scripts'] > 2 else 0
                    
                    # server form handler
                    features['ServerFormHandler'] = 1 if html_info['form_action_external'] else 0
                    
                    # website forwarding
                    features['WebsiteForwarding'] = 1 if html_info['null_links'] > 3 else 0
                    
                    # status bar customization
                    features['StatusBarCust'] = 1 if html_info['status_bar_customized'] else 0
                    
                    # right-click disabled
                    features['DisableRightClick'] = 1 if html_info['has_right_click_disabled'] else 0
                    
                    # popup windows
                    features['UsingPopupWindow'] = 1 if html_info['has_popup'] else 0
                    
                    # iframe redirection
                    features['IframeRedirection'] = 1 if html_info['iframe_count'] > 0 else 0
                    
                except Exception as e:
                    logger.warning(f"Error analyzing HTML content: {e}")
                    # set HTML features to default values
                    features.update({
                        'Favicon': 0, 'RequestURL': 0, 'AnchorURL': 0,
                        'LinksInScriptTags': 0, 'ServerFormHandler': 0, 
                        'WebsiteForwarding': 0, 'StatusBarCust': 0,
                        'DisableRightClick': 0, 'UsingPopupWindow': 0, 
                        'IframeRedirection': 0
                    })
            else:
                # set HTML features to default values for non-HTTP URLs
                features.update({
                    'Favicon': 0, 'RequestURL': 0, 'AnchorURL': 0,
                    'LinksInScriptTags': 0, 'ServerFormHandler': 0, 
                    'WebsiteForwarding': 0, 'StatusBarCust': 0,
                    'DisableRightClick': 0, 'UsingPopupWindow': 0, 
                    'IframeRedirection': 0
                })
                
            # log successful extraction
            logger.info(f"Successfully extracted features for URL: {url[:50]}...")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return DeepFeatureExtractor._get_default_features()
    
    @staticmethod
    def _get_default_features() -> Dict[str, Any]:
        """return default feature set with zeros"""
        return {
            'UsingIP': 0, 'LongURL': 0, 'ShortURL': 0, 'Symbol@': 0,
            'Redirecting//': 0, 'PrefixSuffix-': 0, 'SubDomains': 0,
            'HTTPS': 0, 'DomainRegLen': 0, 'Favicon': 0, 'NonStdPort': 0,
            'HTTPSDomainURL': 0, 'RequestURL': 0, 'AnchorURL': 0,
            'LinksInScriptTags': 0, 'ServerFormHandler': 0, 'InfoEmail': 0,
            'AbnormalURL': 0, 'WebsiteForwarding': 0, 'StatusBarCust': 0,
            'DisableRightClick': 0, 'UsingPopupWindow': 0, 'IframeRedirection': 0,
            'AgeofDomain': 0, 'DNSRecording': 0, 'WebsiteTraffic': 0,
            'PageRank': 0, 'GoogleIndex': 0, 'LinksPointingToPage': 0,
            'StatsReport': 0
        }
    
    @staticmethod
    def _get_domain(url: str) -> tuple:
        """extract domain from URL"""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            if extracted.subdomain:
                full_domain = f"{extracted.subdomain}.{domain}"
            else:
                full_domain = domain
            return domain, full_domain
        except Exception as e:
            logger.error(f"Error extracting domain: {e}")
            return None, None
    
    @staticmethod
    def _is_ip(netloc: str) -> bool:
        """check if the netloc is an IP address"""
        try:
            socket.inet_aton(netloc.split(':')[0])
            return True
        except:
            return False
    
    @staticmethod
    def _get_domain_info(domain: str) -> Dict[str, Any]:
        """get domain registration info using WHOIS"""
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
            logger.warning(f"Error getting domain info: {e}")
            return {
                'domain_age': -1,
                'registration_length': -1
            }
    
    @staticmethod
    def _get_dns_records(domain: str) -> Dict[str, Any]:
        """check if domain has proper DNS records"""
        records = {
            'has_a': False,
            'has_mx': False,
            'has_ns': False,
            'has_txt': False,
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
            
            # TXT record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                records['has_txt'] = len(answers) > 0
                records['total_records'] += len(answers)
            except:
                pass
            
            return records
        except Exception as e:
            logger.warning(f"Error getting DNS records: {e}")
            return records
    
    @staticmethod
    def _analyze_html_content(url: str, domain: str) -> Dict[str, Any]:
        """analyze HTML content for suspicious patterns"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
            }
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code != 200:
                return {
                    'has_favicon': False,
                    'external_favicon': False,
                    'form_action_external': False,
                    'has_password_field': False,
                    'has_hidden_element': False,
                    'external_scripts': 0,
                    'iframe_count': 0,
                    'onclick_count': 0,
                    'external_links': 0,
                    'internal_links': 0,
                    'null_links': 0,
                    'has_right_click_disabled': False,
                    'has_popup': False,
                    'status_bar_customized': False
                }
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # check favicon
            favicon = soup.find('link', rel=lambda r: r and 'icon' in r.lower())
            has_favicon = favicon is not None
            external_favicon = False
            if has_favicon and favicon.get('href'):
                favicon_url = favicon['href']
                if not favicon_url.startswith('data:'):
                    if favicon_url.startswith('http'):
                        favicon_domain = DeepFeatureExtractor._get_domain(favicon_url)[0]
                        external_favicon = favicon_domain != domain
            
            # check forms
            forms = soup.find_all('form')
            form_action_external = False
            for form in forms:
                action = form.get('action', '')
                if action and action.startswith('http'):
                    action_domain = DeepFeatureExtractor._get_domain(action)[0]
                    if action_domain != domain:
                        form_action_external = True
                        break
            
            # check for password fields
            has_password_field = len(soup.find_all('input', type='password')) > 0
            
            # check for hidden elements
            has_hidden_element = len(soup.find_all('input', type='hidden')) > 0
            
            # count scripts from external domains
            scripts = soup.find_all('script', src=True)
            external_scripts = 0
            for script in scripts:
                if script['src'].startswith('http'):
                    script_domain = DeepFeatureExtractor._get_domain(script['src'])[0]
                    if script_domain != domain:
                        external_scripts += 1
            
            # count iframes
            iframe_count = len(soup.find_all('iframe'))
            
            # count onclick events
            elements_with_onclick = soup.find_all(lambda tag: tag.has_attr('onclick'))
            onclick_count = len(elements_with_onclick)
            
            # analyze links
            links = soup.find_all('a', href=True)
            external_links = 0
            internal_links = 0
            null_links = 0
            
            for link in links:
                href = link['href'].lower()
                if href == '#' or href == 'javascript:void(0)':
                    null_links += 1
                elif href.startswith('http'):
                    link_domain = DeepFeatureExtractor._get_domain(href)[0]
                    if link_domain != domain:
                        external_links += 1
                    else:
                        internal_links += 1
                else:
                    internal_links += 1
            
            # check for right-click disabling
            has_right_click_disabled = 'oncontextmenu="return false"' in response.text or 'event.button==2' in response.text
            
            # check for popups
            has_popup = 'window.open(' in response.text
            
            # check for status bar customization
            status_bar_customized = 'window.status' in response.text
            
            return {
                'has_favicon': has_favicon,
                'external_favicon': external_favicon,
                'form_action_external': form_action_external,
                'has_password_field': has_password_field,
                'has_hidden_element': has_hidden_element,
                'external_scripts': external_scripts,
                'iframe_count': iframe_count,
                'onclick_count': onclick_count,
                'external_links': external_links,
                'internal_links': internal_links,
                'null_links': null_links,
                'has_right_click_disabled': has_right_click_disabled,
                'has_popup': has_popup,
                'status_bar_customized': status_bar_customized
            }
        except Exception as e:
            logger.error(f"Error analyzing HTML content: {e}")
            return {
                'has_favicon': False,
                'external_favicon': False,
                'form_action_external': False,
                'has_password_field': False,
                'has_hidden_element': False,
                'external_scripts': 0,
                'iframe_count': 0,
                'onclick_count': 0,
                'external_links': 0,
                'internal_links': 0,
                'null_links': 0,
                'has_right_click_disabled': False,
                'has_popup': False,
                'status_bar_customized': False
            }
    
    @staticmethod
    def prepare_features_for_model(features: Dict[str, Any], feature_list: List[str]) -> np.ndarray:
        """create a feature array with values in the correct order"""
        feature_array = []
        for feature_name in feature_list:
            feature_array.append(features.get(feature_name, 0))
        
        return np.array(feature_array).reshape(1, -1)