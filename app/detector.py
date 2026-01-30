"""
Main Phishing Detection Engine
Combines blacklist, heuristic, and ML-based detection
"""
import os
import joblib
import re
from urllib.parse import urlparse
import tldextract
import config
from app.feature_extractor import FeatureExtractor

class PhishingDetector:
    """Multi-layer phishing detection system"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.blacklist = self._load_blacklist()
        self.model = None
        self.scaler = None
        self._load_model()
    
    def _load_blacklist(self):
        """Load blacklist of known phishing domains"""
        blacklist = set()
        if os.path.exists(config.BLACKLIST_PATH):
            with open(config.BLACKLIST_PATH, 'r') as f:
                blacklist = set(line.strip().lower() for line in f if line.strip())
        return blacklist
    
    def _load_model(self):
        """Load trained ML model and scaler"""
        try:
            if os.path.exists(config.MODEL_PATH):
                self.model = joblib.load(config.MODEL_PATH)
            if os.path.exists(config.SCALER_PATH):
                self.scaler = joblib.load(config.SCALER_PATH)
        except Exception as e:
            print(f"Warning: Could not load model: {e}")
    
    def detect(self, url):
        """
        Main detection method
        Returns: dict with detection results
        """
        # Normalize URL
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Initialize result
        result = {
            'url': url,
            'is_phishing': False,
            'risk_score': 0.0,
            'risk_level': 'Low',
            'detection_methods': [],
            'warnings': [],
            'features': {}
        }
        
        # Layer 1: Blacklist Check
        blacklist_score = self._check_blacklist(url)
        
        # Layer 2: Heuristic Analysis
        heuristic_score, heuristic_warnings = self._heuristic_analysis(url)
        
        # Layer 3: ML Classification
        ml_score = self._ml_classification(url)
        
        # Extract features for display
        result['features'] = self.feature_extractor.extract_features(url)
        
        # Calculate weighted risk score
        weights = config.FEATURE_WEIGHTS
        result['risk_score'] = (
            blacklist_score * weights['blacklist'] +
            heuristic_score * weights['heuristic'] +
            ml_score * weights['ml_model']
        )
        
        # Determine risk level
        result['risk_level'] = self._get_risk_level(result['risk_score'])
        result['is_phishing'] = result['risk_score'] >= config.RISK_THRESHOLDS['medium']
        
        # Add warnings
        result['warnings'] = heuristic_warnings
        
        # Add detection methods used
        if blacklist_score > 0:
            result['detection_methods'].append('Blacklist')
        if heuristic_score > 0.5:
            result['detection_methods'].append('Heuristic Analysis')
        if ml_score > 0.5:
            result['detection_methods'].append('Machine Learning')
        
        return result
    
    def _check_blacklist(self, url):
        """Check if URL is in blacklist"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check exact domain
        if domain in self.blacklist:
            return 1.0
        
        # Check base domain
        ext = tldextract.extract(url)
        base_domain = f"{ext.domain}.{ext.suffix}".lower()
        if base_domain in self.blacklist:
            return 1.0
        
        return 0.0
    
    def _heuristic_analysis(self, url):
        """Apply heuristic rules for phishing detection"""
        score = 0.0
        warnings = []
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        weights = config.HEURISTIC_WEIGHTS
        
        # Rule 1: IP Address instead of domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
            score += weights['ip_address']
            warnings.append("Uses IP address instead of domain name")
        
        # Rule 2: Very long URL
        if len(url) > 75:
            score += weights['long_url']
            warnings.append(f"Unusually long URL ({len(url)} characters)")
        
        # Rule 3: URL shortener
        if any(short in parsed.netloc for short in config.URL_SHORTENERS):
            score += weights['shortened_url']
            warnings.append("Uses URL shortening service")
        
        # Rule 4: @ symbol in URL
        if '@' in url:
            score += weights['at_symbol']
            warnings.append("Contains @ symbol (possible redirect)")
        
        # Rule 5: Double slash in path
        if '//' in parsed.path:
            score += weights['double_slash']
            warnings.append("Double slash in path (possible redirect)")
        
        # Rule 6: Many hyphens in domain
        if parsed.netloc.count('-') > 2:
            score += weights['dash_in_domain']
            warnings.append("Multiple hyphens in domain name")
        
        # Rule 7: Too many subdomains
        subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
        if subdomain_count > 2:
            score += weights['subdomain_count']
            warnings.append(f"Excessive subdomains ({subdomain_count})")
        
        # Rule 8: No HTTPS
        if parsed.scheme != 'https':
            score += weights['https']
            warnings.append("Not using secure HTTPS protocol")
        
        # Rule 9: Suspicious keywords
        if any(keyword in url.lower() for keyword in config.SUSPICIOUS_KEYWORDS):
            score += weights['suspicious_keywords']
            warnings.append("Contains suspicious keywords")
        
        return min(score, 1.0), warnings
    
    def _ml_classification(self, url):
        """Use ML model for classification"""
        if self.model is None or self.scaler is None:
            return 0.5  # Neutral score if model not available
        
        try:
            # Extract features
            features = self.feature_extractor.get_feature_vector(url)
            
            # Scale features
            features_scaled = self.scaler.transform([features])
            
            # Predict probability
            prob = self.model.predict_proba(features_scaled)[0]
            
            # Return probability of being phishing (class 1)
            return prob[1]
        
        except Exception as e:
            print(f"ML classification error: {e}")
            return 0.5
    
    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        thresholds = config.RISK_THRESHOLDS
        
        if score < thresholds['low']:
            return 'Low'
        elif score < thresholds['medium']:
            return 'Medium'
        elif score < thresholds['high']:
            return 'High'
        else:
            return 'Critical'
    
    def get_stats(self):
        """Get detector statistics"""
        return {
            'blacklist_size': len(self.blacklist),
            'model_loaded': self.model is not None,
            'features_count': 28,
            'detection_layers': 3
        }
