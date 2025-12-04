@echo off
REM Launch Streamlit app for MEEF Malware Detection

echo ========================================
echo  MEEF Malware Detection - Streamlit UI
echo ========================================
echo.

REM Check if streamlit is installed
python -c "import streamlit" 2>NUL
if errorlevel 1 (
    echo [!] Streamlit not found. Installing dependencies...
    pip install -r requirements.txt
    echo.
)

echo [*] Launching Streamlit app...
echo [*] The app will open in your browser automatically
echo [*] Press Ctrl+C to stop the server
echo.

streamlit run streamlit_app.py
