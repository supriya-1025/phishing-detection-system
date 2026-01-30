"""
Train Machine Learning Model for Phishing Detection
Trains a Random Forest classifier on sample data
"""
import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import config
from app.feature_extractor import FeatureExtractor

def generate_sample_data(n_samples=1000):
    """
    Generate sample training data
    In production, replace this with real phishing dataset
    """
    print("Generating sample training data...")
    
    # Sample legitimate URLs
    legitimate_urls = [
        "https://www.google.com",
        "https://www.facebook.com",
        "https://www.amazon.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.reddit.com",
        "https://www.wikipedia.org",
        "https://www.youtube.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.netflix.com",
        "https://docs.python.org",
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.nytimes.com",
        "https://www.espn.com"
    ]
    
    # Sample phishing URLs (for training purposes only)
    phishing_urls = [
        "http://paypal-verify.com/account",
        "http://secure-amazon.ru/login",
        "http://192.168.1.1/banking",
        "http://apple-id-verify.tk/signin",
        "http://www.google.com-verify.ml",
        "http://netflix.account-update.ga",
        "http://secure.facebook.confirm-account.cf",
        "http://microsoft-security-alert.tk",
        "http://account-suspended-amazon.ml",
        "http://paypal.com-secure-login.tk",
        "http://verify-your-account.bit.ly",
        "http://instagram.com.login-verify.ga",
        "http://twitter.com-account-suspended.tk",
        "http://linkedin-verify.ml/update",
        "http://your-account-limited.tk",
        "http://urgent-security-alert.ml",
        "http://confirm-your-identity.ga"
    ]
    
    # Generate variations
    urls = []
    labels = []
    
    # Legitimate variations
    for _ in range(n_samples // 2):
        base_url = np.random.choice(legitimate_urls)
        # Add some variations
        if np.random.random() > 0.5:
            base_url += "/page/" + str(np.random.randint(1, 100))
        urls.append(base_url)
        labels.append(0)  # 0 = legitimate
    
    # Phishing variations
    for _ in range(n_samples // 2):
        base_url = np.random.choice(phishing_urls)
        # Add some variations
        if np.random.random() > 0.5:
            base_url += "?id=" + str(np.random.randint(1000, 9999))
        urls.append(base_url)
        labels.append(1)  # 1 = phishing
    
    return urls, labels

def extract_features_from_urls(urls):
    """Extract features from list of URLs"""
    print("Extracting features from URLs...")
    extractor = FeatureExtractor()
    
    features = []
    for url in urls:
        feature_vector = extractor.get_feature_vector(url)
        features.append(feature_vector)
    
    return np.array(features)

def train_model():
    """Train the phishing detection model"""
    print("\n" + "="*60)
    print("PHISHING DETECTION MODEL TRAINING")
    print("="*60 + "\n")
    
    # Generate or load data
    urls, labels = generate_sample_data(n_samples=1000)
    
    # Extract features
    X = extract_features_from_urls(urls)
    y = np.array(labels)
    
    print(f"Dataset size: {len(urls)} URLs")
    print(f"Legitimate URLs: {np.sum(y == 0)}")
    print(f"Phishing URLs: {np.sum(y == 1)}")
    print(f"Features extracted: {X.shape[1]}\n")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Training set: {} samples".format(len(X_train)))
    print("Test set: {} samples\n".format(len(X_test)))
    
    # Scale features
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest model
    print("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    print("Training completed!\n")
    
    # Evaluate model
    print("="*60)
    print("MODEL EVALUATION")
    print("="*60 + "\n")
    
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Accuracy: {accuracy:.2%}\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print("\n[[True Negatives, False Positives]")
    print(" [False Negatives, True Positives]]\n")
    
    # Feature importance
    feature_names = [
        'url_length', 'domain_length', 'has_ip', 'has_at_symbol',
        'double_slash_redirect', 'subdomain_count', 'is_https',
        'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
        'num_question_marks', 'num_equals', 'num_ampersands',
        'num_digits', 'num_params', 'path_length', 'has_suspicious_keyword',
        'is_shortener', 'has_brand_name', 'url_entropy', 'domain_entropy',
        'digit_ratio', 'has_port', 'tld_length', 'has_punycode',
        'consecutive_consonants', 'special_char_ratio'
    ]
    
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("Top 10 Most Important Features:")
    print(feature_importance.head(10).to_string(index=False))
    print()
    
    # Save model and scaler
    print("="*60)
    print("SAVING MODEL")
    print("="*60 + "\n")
    
    os.makedirs(config.MODEL_DIR, exist_ok=True)
    
    joblib.dump(model, config.MODEL_PATH)
    print(f"✓ Model saved to: {config.MODEL_PATH}")
    
    joblib.dump(scaler, config.SCALER_PATH)
    print(f"✓ Scaler saved to: {config.SCALER_PATH}")
    
    print("\n" + "="*60)
    print("TRAINING COMPLETED SUCCESSFULLY!")
    print("="*60 + "\n")
    
    return model, scaler, accuracy

if __name__ == '__main__':
    train_model()
