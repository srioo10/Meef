#!/bin/bash
# Launch Streamlit app for MEEF Malware Detection

echo "========================================"
echo " MEEF Malware Detection - Streamlit UI"
echo "========================================"
echo ""

# Check if streamlit is installed
if ! python3 -c "import streamlit" 2>/dev/null; then
    echo "[!] Streamlit not found. Installing dependencies..."
    pip3 install -r requirements.txt
    echo ""
fi

echo "[*] Launching Streamlit app..."
echo "[*] The app will open in your browser automatically"
echo "[*] Press Ctrl+C to stop the server"
echo ""

streamlit run streamlit_app.py
