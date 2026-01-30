#!/bin/bash

echo "============================================================"
echo "PHISHING DETECTION SYSTEM - Setup Script (macOS/Linux)"
echo "============================================================"
echo ""

echo "Step 1: Installing Python dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi
echo ""

echo "Step 2: Downloading NLTK data..."
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to download NLTK data"
    exit 1
fi
echo ""

echo "Step 3: Training machine learning model..."
python app/train_model.py
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to train model"
    exit 1
fi
echo ""

echo "============================================================"
echo "SETUP COMPLETED SUCCESSFULLY!"
echo "============================================================"
echo ""
echo "To run the application, execute:"
echo "    python app.py"
echo ""
echo "Then open your browser to: http://localhost:5000"
echo ""
