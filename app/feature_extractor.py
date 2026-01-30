"""
Feature Extraction Module for Phishing Detection
Extracts 28 features from URLs for ML classification
"""
import re
import math
from urllib.parse import urlparse, parse_qs
import tldextract
import config

class FeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.suspicious_keywords = config.SUSPICIOUS_KEYWORDS
        self.brand_names = config.BRAND_NAMES
        self.url_shorteners = config.URL_SHORTENERS
    
    def extract_features(self, url):
        """
        Extract all 28 features from a URL
        Returns: dict with feature names and values
        """
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        # 1. URL Length
        features['url_length'] = len(url)
        
        # 2. Domain Length
        features['domain_length'] = len(parsed.netloc)
        
        # 3. Has IP Address
        features['has_ip'] = self._has_ip_address(parsed.netloc)
        
        # 4. Has @ Symbol
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # 5. Has Double Slash in Path
        features['double_slash_redirect'] = 1 if '//' in parsed.path else 0
        
        # 6. Number of Subdomains
        features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
        
        # 7. Uses HTTPS
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        
        # 8. Number of Dots
        features['num_dots'] = url.count('.')
        
        # 9. Number of Hyphens
        features['num_hyphens'] = url.count('-')
        
        # 10. Number of Underscores
        features['num_underscores'] = url.count('_')
        
        # 11. Number of Slashes
        features['num_slashes'] = url.count('/')
        
        # 12. Number of Question Marks
        features['num_question_marks'] = url.count('?')
        
        # 13. Number of Equal Signs
        features['num_equals'] = url.count('=')
        
        # 14. Number of Ampersands
        features['num_ampersands'] = url.count('&')
        
        # 15. Number of Digits
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # 16. Number of Query Parameters
        features['num_params'] = len(parse_qs(parsed.query))
        
        # 17. Path Length
        features['path_length'] = len(parsed.path)
        
        # 18. Has Suspicious Keywords
        features['has_suspicious_keyword'] = self._has_suspicious_keywords(url.lower())
        
        # 19. Is URL Shortener
        features['is_shortener'] = 1 if any(short in parsed.netloc for short in self.url_shorteners) else 0
        
        # 20. Has Brand Name
        features['has_brand_name'] = self._has_brand_spoofing(url.lower(), ext.domain.lower())
        
        # 21. Entropy of URL
        features['url_entropy'] = self._calculate_entropy(url)
        
        # 22. Entropy of Domain
        features['domain_entropy'] = self._calculate_entropy(parsed.netloc)
        
        # 23. Ratio of Digits to Length
        features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
        
        # 24. Has Port Number
        features['has_port'] = 1 if parsed.port else 0
        
        # 25. TLD Length
        features['tld_length'] = len(ext.suffix)
        
        # 26. Has Punycode
        features['has_punycode'] = 1 if 'xn--' in url else 0
        
        # 27. Consecutive Consonants Count
        features['consecutive_consonants'] = self._max_consecutive_consonants(parsed.netloc)
        
        # 28. Special Character Ratio
        special_chars = sum(not c.isalnum() for c in url)
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
        return features
    
    def _has_ip_address(self, domain):
        """Check if domain is an IP address"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return 1 if re.match(ip_pattern, domain) else 0
    
    def _has_suspicious_keywords(self, url):
        """Check for suspicious keywords"""
        return 1 if any(keyword in url for keyword in self.suspicious_keywords) else 0
    
    def _has_brand_spoofing(self, url, domain):
        """Check for brand name spoofing"""
        for brand in self.brand_names:
            if brand in url and brand not in domain:
                return 1
        return 0
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        return entropy
    
    def _max_consecutive_consonants(self, text):
        """Find maximum consecutive consonants"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        max_count = 0
        current_count = 0
        
        for char in text.lower():
            if char in consonants:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def get_feature_vector(self, url):
        """
        Get feature vector as list (for ML model)
        Returns: list of 28 feature values
        """
        features = self.extract_features(url)
        
        # Define feature order (important for ML model)
        feature_order = [
            'url_length', 'domain_length', 'has_ip', 'has_at_symbol',
            'double_slash_redirect', 'subdomain_count', 'is_https',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equals', 'num_ampersands',
            'num_digits', 'num_params', 'path_length', 'has_suspicious_keyword',
            'is_shortener', 'has_brand_name', 'url_entropy', 'domain_entropy',
            'digit_ratio', 'has_port', 'tld_length', 'has_punycode',
            'consecutive_consonants', 'special_char_ratio'
        ]
        
        return [features[f] for f in feature_order]
