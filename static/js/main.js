// Main JavaScript for Phishing Detection System

document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const urlInput = document.getElementById('urlInput');
    const checkBtn = document.getElementById('checkBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const testButtons = document.querySelectorAll('.test-btn');

    // Event Listeners
    checkBtn.addEventListener('click', analyzeURL);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeURL();
        }
    });

    // Quick test buttons
    testButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            urlInput.value = this.dataset.url;
            analyzeURL();
        });
    });

    // Smooth scroll for navigation
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // Main Analysis Function
    async function analyzeURL() {
        const url = urlInput.value.trim();

        if (!url) {
            showError('Please enter a URL to analyze');
            return;
        }

        // Show loading, hide results
        loading.classList.remove('hidden');
        results.classList.add('hidden');

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (response.ok) {
                displayResults(data);
            } else {
                showError(data.error || 'Analysis failed');
            }
        } catch (error) {
            showError('Network error: ' + error.message);
        } finally {
            loading.classList.add('hidden');
        }
    }

    // Display Results
    function displayResults(data) {
        const riskColor = getRiskColor(data.risk_level);
        const riskScore = (data.risk_score * 100).toFixed(1);

        let html = `
            <div class="result-header">
                <div class="result-url">
                    <strong>URL:</strong> ${escapeHtml(data.url)}
                </div>
                <div class="risk-badge risk-${data.risk_level.toLowerCase()}">
                    ${data.risk_level} Risk
                </div>
            </div>

            <div class="risk-score">
                <h3>Risk Score: ${riskScore}%</h3>
                <div class="score-bar-container">
                    <div class="score-bar" style="width: ${riskScore}%; background: ${riskColor}">
                        ${riskScore}%
                    </div>
                </div>
            </div>

            <div class="detection-methods">
                <h3>Detection Methods Used:</h3>
                <div class="method-tags">
                    ${data.detection_methods.length > 0 
                        ? data.detection_methods.map(method => `
                            <span class="method-tag">${method}</span>
                        `).join('')
                        : '<span class="method-tag">Baseline Analysis</span>'
                    }
                </div>
            </div>
        `;

        // Add warnings if any
        if (data.warnings && data.warnings.length > 0) {
            html += `
                <div class="warnings">
                    <h3>⚠️ Warnings Detected:</h3>
                    ${data.warnings.map(warning => `
                        <div class="warning-item">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span>${warning}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        // Add recommendations
        html += getRecommendations(data.risk_level, data.is_phishing);

        results.innerHTML = html;
        results.classList.remove('hidden');

        // Scroll to results
        results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Get Risk Color
    function getRiskColor(level) {
        const colors = {
            'Low': '#10b981',
            'Medium': '#f59e0b',
            'High': '#ef4444',
            'Critical': '#dc2626'
        };
        return colors[level] || '#6b7280';
    }

    // Get Recommendations
    function getRecommendations(riskLevel, isPhishing) {
        let recommendations = [];

        if (isPhishing) {
            recommendations = [
                '🚫 Do NOT click on this link or visit this website',
                '🔒 Do NOT enter any personal information',
                '📧 If received via email, mark as spam and delete',
                '👥 Report this URL to your IT department or security team',
                '🛡️ Run a security scan on your device if you visited this site'
            ];
        } else if (riskLevel === 'Medium') {
            recommendations = [
                '⚠️ Exercise caution when visiting this URL',
                '🔍 Verify the website is legitimate before entering information',
                '🔒 Ensure the connection is secure (HTTPS)',
                '📱 Consider using a security tool for additional verification'
            ];
        } else {
            recommendations = [
                '✅ URL appears safe based on our analysis',
                '🔒 Still verify HTTPS connection before entering sensitive data',
                '🧐 Be cautious of any unusual behavior on the website',
                '💡 Always stay vigilant when browsing online'
            ];
        }

        return `
            <div class="recommendations">
                <h3>💡 Recommendations:</h3>
                <ul>
                    ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Show Error
    function showError(message) {
        results.innerHTML = `
            <div class="result-header">
                <div class="risk-badge risk-high">
                    Error
                </div>
            </div>
            <div class="warnings">
                <div class="warning-item">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>${escapeHtml(message)}</span>
                </div>
            </div>
        `;
        results.classList.remove('hidden');
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});
