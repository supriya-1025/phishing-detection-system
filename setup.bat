@echo off
echo ============================================================
echo PHISHING DETECTION SYSTEM - Setup Script (Windows)
echo ============================================================
echo.

echo Step 1: Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo.

echo Step 2: Downloading NLTK data...
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
if %errorlevel% neq 0 (
    echo ERROR: Failed to download NLTK data
    pause
    exit /b 1
)
echo.

echo Step 3: Training machine learning model...
python app\train_model.py
if %errorlevel% neq 0 (
    echo ERROR: Failed to train model
    pause
    exit /b 1
)
echo.

echo ============================================================
echo SETUP COMPLETED SUCCESSFULLY!
echo ============================================================
echo.
echo To run the application, execute:
echo     python app.py
echo.
echo Then open your browser to: http://localhost:5000
echo.
pause
