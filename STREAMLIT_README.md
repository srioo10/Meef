# 🛡️ MEEF Malware Detection - Streamlit Interface

A beautiful web interface for analyzing executable files and detecting malware using machine learning.

## Features

- 📁 **File Upload**: Support for `.exe`, `.dll`, and `.asm` files
- 🔍 **Automatic Conversion**: Converts executables to assembly using `objdump`
- ✅ **ASM Validation**: Checks file format and assembly code structure
- 🤖 **ML Prediction**: Uses trained machine learning model to detect malware
- 📊 **Visual Results**: Beautiful confidence scores and risk level displays
- 💾 **Download ASM**: Export disassembled files for further analysis

## Quick Start

### 1. Install Dependencies

```bash
# Windows
pip install -r requirements.txt

# Linux/Mac
pip3 install -r requirements.txt
```

### 2. Train the Model (if not already done)

```bash
python data/models/train_model.py
```

### 3. Launch the App

**Windows:**
```bash
run_streamlit.bat
```

**Linux/Mac:**
```bash
chmod +x run_streamlit.sh
./run_streamlit.sh
```

**Or manually:**
```bash
streamlit run streamlit_app.py
```

The app will automatically open in your browser at `http://localhost:8501`

## How It Works

### Workflow

```
┌─────────────────┐
│  Upload File    │
│ (.exe/.asm/.dll)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Is ASM file?   │
└────┬───────┬────┘
     │ NO    │ YES
     ▼       ▼
┌──────┐  ┌──────┐
│Disas │  │Valid-│
│semble│  │ date │
└───┬──┘  └───┬──┘
    └────┬────┘
         ▼
┌─────────────────┐
│ Extract Features│
│  (via MEEF)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ML Prediction  │
│  (Random Forest)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Display Results │
│ - Classification│
│ - Confidence    │
│ - Risk Level    │
└─────────────────┘
```

### Components Used

1. **`validate_asm.py`**: Validates assembly files and checks for binary format
2. **`disassemble.sh`**: Converts executables to assembly using `objdump`
3. **`data/models/predict.py`**: ML-based malware prediction engine
4. **`streamlit_app.py`**: Web interface tying everything together

## Interface Overview

### Upload Section
- Drag and drop or browse for files
- Supported formats: `.exe`, `.dll`, `.asm`
- File size and info displayed

### Analysis Progress
- **Step 1/3**: File validation and conversion
- **Step 2/3**: Assembly code preview
- **Step 3/3**: ML prediction

### Results Display
- ✅ **Benign** or 🚨 **Malicious** classification
- **Confidence score** (0-100%)
- **Risk level**: 🟢 LOW, 🟡 MEDIUM, 🟠 HIGH, 🔴 CRITICAL
- **Probability distribution** for both classes

## Requirements

### Software
- Python 3.7+
- Git Bash (Windows only) - for running `disassemble.sh`
- objdump (usually comes with binutils)

### Python Packages
See `requirements.txt`:
- streamlit
- numpy
- pandas
- scikit-learn
- joblib
- And other MEEF dependencies

### Installing Git Bash (Windows)
If you're on Windows and haven't installed Git:
1. Download from: https://git-scm.com/download/win
2. Run the installer
3. Git Bash will be installed at `C:\Program Files\Git\bin\bash.exe`

## Tips

### For Best Results
1. **Train the model first**: Ensure you have a trained model in `data/models/`
2. **Use real samples**: Test with actual malware samples (in a safe environment!)
3. **Assembly files**: If you already have `.asm` files, upload them directly

### Troubleshooting

**"Model not found" error:**
```bash
python data/models/train_model.py
```

**"Git Bash not found" (Windows):**
- Install Git for Windows: https://git-scm.com/download/win
- Or edit `streamlit_app.py` and update the bash path

**Disassembly fails:**
- Ensure `objdump` is installed: `sudo apt install binutils` (Linux)
- Check if the executable is a valid PE file

## Screenshots Preview

The interface includes:
- Modern gradient header
- Clean upload interface
- Step-by-step progress tracking
- Color-coded results (red for malicious, green for benign)
- Detailed probability metrics
- ASM code preview
- Download options

## Security Notice

⚠️ **Warning**: This tool is for **educational and research purposes only**. 

- Always analyze malware in isolated/sandboxed environments
- Don't upload sensitive or production files
- ML predictions are not 100% accurate
- Use alongside other security tools

## Advanced Usage

### Custom Model Path
Edit `streamlit_app.py` line containing `MalwarePredictor()`:
```python
predictor = MalwarePredictor(model_dir="path/to/your/models")
```

### Batch Analysis
The current interface handles one file at a time. For batch processing, use the command-line tools directly.

## Contributing

Feel free to enhance the interface:
- Add more visualizations
- Support more file formats
- Improve the ML model
- Add feature importance display

## License

Part of the MEEF project - Machine Learning Enhanced Executable Forensics

---

**Built with ❤️ using Streamlit and MEEF**
