"""
Configuration settings for Phishing Detection System
"""
import os

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Model paths
MODEL_DIR = os.path.join(BASE_DIR, 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_detector.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')

# Data paths
DATA_DIR = os.path.join(BASE_DIR, 'data')
BLACKLIST_PATH = os.path.join(DATA_DIR, 'blacklist.txt')

# Flask settings
SECRET_KEY = 'your-secret-key-change-this-in-production'
DEBUG = True
HOST = '0.0.0.0'
PORT = 5000

# Detection thresholds
RISK_THRESHOLDS = {
    'low': 0.3,
    'medium': 0.6,
    'high': 0.8
}

# Feature weights for scoring
FEATURE_WEIGHTS = {
    'blacklist': 0.4,
    'heuristic': 0.3,
    'ml_model': 0.3
}

# Heuristic rules weights
HEURISTIC_WEIGHTS = {
    'ip_address': 0.15,
    'long_url': 0.10,
    'shortened_url': 0.12,
    'at_symbol': 0.15,
    'double_slash': 0.08,
    'dash_in_domain': 0.10,
    'subdomain_count': 0.10,
    'https': 0.10,
    'suspicious_keywords': 0.10
}

# Suspicious keywords for phishing detection
SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'suspended', 'limited', 'update', 'confirm',
    'secure', 'banking', 'login', 'signin', 'ebay', 'paypal', 'amazon',
    'alert', 'notification', 'urgent', 'immediate', 'action', 'required'
]

# Brand names to check for spoofing
BRAND_NAMES = [
    'google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple',
    'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'yahoo'
]

# URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'buff.ly',
    'is.gd', 'cli.gs', 'pic.gd', 'DwarfURL.com', 'yfrog.com'
]
