"""
Initialize Flask application
"""
from flask import Flask
import os

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    
    # Load configuration
    app.config.from_object('config')
    
    # Ensure required directories exist
    os.makedirs(app.config['MODEL_DIR'], exist_ok=True)
    os.makedirs(app.config['DATA_DIR'], exist_ok=True)
    
    return app
