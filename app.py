"""
Main Flask Application for Phishing Detection System
"""
from flask import Flask, render_template, request, jsonify
import config
from app.detector import PhishingDetector

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config')

# Initialize detector
detector = PhishingDetector()

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """
    Analyze a single URL
    Expected JSON: {"url": "http://example.com"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'No URL provided'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'error': 'Empty URL provided'
            }), 400
        
        # Perform detection
        result = detector.detect(url)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f'Analysis failed: {str(e)}'
        }), 500

@app.route('/api/batch', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple URLs
    Expected JSON: {"urls": ["url1", "url2", ...]}
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'No URLs provided'
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({
                'error': 'URLs must be a list'
            }), 400
        
        if len(urls) > 100:
            return jsonify({
                'error': 'Maximum 100 URLs allowed'
            }), 400
        
        # Analyze each URL
        results = []
        for url in urls:
            if url.strip():
                result = detector.detect(url.strip())
                results.append(result)
        
        return jsonify({
            'results': results,
            'total': len(results)
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Batch analysis failed: {str(e)}'
        }), 500

@app.route('/api/stats')
def get_stats():
    """Get detector statistics"""
    try:
        stats = detector.get_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({
            'error': f'Failed to get stats: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("PHISHING DETECTION SYSTEM - Starting Server")
    print("="*60)
    print(f"\n✓ Server running at: http://{config.HOST}:{config.PORT}")
    print("✓ Press CTRL+C to stop\n")
    print("="*60 + "\n")
    
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )
