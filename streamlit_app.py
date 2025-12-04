#!/usr/bin/env python3
"""
Streamlit Interface for MEEF Malware Detection
Provides a web UI for analyzing malware samples
"""

import streamlit as st
import subprocess
import sys
import json
import tempfile
import shutil
from pathlib import Path
import os

# Import existing modules
sys.path.append(str(Path(__file__).parent))
from validate_asm import is_binary, preview_asm
from data.models.predict import MalwarePredictor


def setup_page():
    """Configure Streamlit page"""
    st.set_page_config(
        page_title="MEEF Malware Detector",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    
    # Custom CSS for better styling with improved contrast
    st.markdown("""
        <style>
        /* Main header with vibrant gradient */
        .main-header {
            font-size: 3rem;
            font-weight: bold;
            text-align: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            padding: 1rem 0;
            margin-bottom: 0.5rem;
        }
        
        /* Subtitle with better contrast */
        .subtitle {
            text-align: center;
            font-size: 1.2rem;
            color: #4a5568;
            margin-bottom: 2rem;
        }
        
        /* Upload box */
        .upload-box {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 2rem;
            text-align: center;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }
        
        /* Result boxes with better contrast */
        .result-box {
            padding: 2rem;
            border-radius: 15px;
            margin: 1.5rem 0;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .malicious {
            background: linear-gradient(135deg, #742a2a 0%, #9b2c2c 100%);
            border-left: 6px solid #fc8181;
            color: #fff;
        }
        .benign {
            background: linear-gradient(135deg, #22543d 0%, #276749 100%);
            border-left: 6px solid #68d391;
            color: #fff;
        }
        
        /* Status indicators */
        .step-success {
            color: #38a169;
            font-weight: bold;
        }
        .step-error {
            color: #e53e3e;
            font-weight: bold;
        }
        
        /* Metric cards */
        div[data-testid="metric-container"] {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
        }
        div[data-testid="metric-container"] label {
            color: #e0e0e0 !important;
        }
        div[data-testid="metric-container"] div {
            color: white !important;
        }
        
        /* Progress bars */
        .stProgress > div > div > div {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }
        
        /* Buttons */
        .stButton > button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            font-size: 1.1rem;
            font-weight: bold;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(102, 126, 234, 0.4);
        }
        
        /* Sidebar styling - Dark Theme */
        section[data-testid="stSidebar"] {
            background-color: #1a202c;
            color: #e2e8f0;
        }
        section[data-testid="stSidebar"] h1, 
        section[data-testid="stSidebar"] h2, 
        section[data-testid="stSidebar"] h3 {
            color: #f7fafc !important;
        }
        section[data-testid="stSidebar"] p, 
        section[data-testid="stSidebar"] li,
        section[data-testid="stSidebar"] div {
            color: #cbd5e0 !important;
        }
        
        /* Expander */
        .streamlit-expanderHeader {
            background-color: #f7fafc;
            border-radius: 10px;
            font-weight: bold;
            color: #2d3748 !important;
        }
        
        /* Code blocks */
        .stCodeBlock {
            background: #2d3748;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        
        /* Info/Warning/Error boxes */
        .stAlert {
            border-radius: 10px;
            border-left-width: 6px;
        }
        </style>
    """, unsafe_allow_html=True)


def display_header():
    """Display app header"""
    st.markdown('<h1 class="main-header">🛡️ MEEF Malware Detector</h1>', unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("""
        <div class='subtitle'>
            Upload an executable or assembly file to analyze for malware
        </div>
    """, unsafe_allow_html=True)
    st.markdown("")


def validate_asm_file(filepath):
    """Validate if file is a valid ASM file"""
    try:
        if is_binary(filepath):
            return False, "File is binary, needs disassembly"
        
        # Check for assembly opcodes
        opcodes = ['MOV', 'CALL', 'JMP', 'PUSH', 'POP', 'RET', 'ADD', 'SUB']
        with open(filepath, 'r') as f:
            content = f.read().upper()
            opcode_found = any(op in content for op in opcodes)
        
        if opcode_found:
            return True, "Valid ASM file detected"
        else:
            return False, "No assembly opcodes found"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def find_bash():
    """Find bash executable on the system - prioritizes WSL on Windows"""
    if os.name == 'nt':
        # On Windows, we REQUIRE WSL for objdump support
        # Check if WSL is available
        try:
            result = subprocess.run(
                ['wsl', '--status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # WSL is available, use it
                return 'wsl'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # WSL not found - return None to trigger error message
        return None
    else:
        # Linux/Mac - use native bash
        return 'bash'


def check_objdump_available(bash_path):
    """Check if objdump is available in the bash environment"""
    try:
        if bash_path == 'wsl':
            # Check objdump in WSL - try both 'which' and direct execution
            # First try 'which objdump'
            result = subprocess.run(
                ['wsl', 'which', 'objdump'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return True
            
            # Fallback: try running objdump directly
            result = subprocess.run(
                ['wsl', 'objdump', '--version'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            return result.returncode == 0
        else:
            # Check objdump in native bash
            result = subprocess.run(
                [bash_path, '-c', 'which objdump'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return True
            
            # Fallback: try running objdump directly
            result = subprocess.run(
                [bash_path, '-c', 'objdump --version'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        # If any error occurs, assume not available
        return False


def windows_path_to_wsl(windows_path):
    """Convert Windows path to WSL path"""
    # Convert C:\Users\... to /mnt/c/Users/...
    path = Path(windows_path)
    path_str = str(path.resolve())
    
    # Get drive letter and path
    if ':' in path_str:
        drive, rest = path_str.split(':', 1)
        drive = drive.lower()
        rest = rest.replace('\\', '/')
        wsl_path = f"/mnt/{drive}{rest}"
        return wsl_path
    return path_str.replace('\\', '/')


def wsl_path_to_windows(wsl_path):
    """Convert WSL path to Windows path"""
    # Convert /mnt/c/Users/... to C:\Users\...
    if wsl_path.startswith('/mnt/'):
        parts = wsl_path[5:].split('/', 1)
        if len(parts) == 2:
            drive = parts[0].upper()
            rest = parts[1].replace('/', '\\')
            return f"{drive}:\\{rest}"
    return wsl_path


def validate_exe_file(exe_path):
    """Validate if file is a valid executable"""
    try:
        # Check if file is binary
        with open(exe_path, 'rb') as f:
            header = f.read(2)
            # Check for PE header (MZ)
            if header == b'MZ':
                return True, "Valid PE executable"
            # Check for ELF header
            elif header == b'\x7fE':
                return True, "Valid ELF executable"
            else:
                # Still might be valid, try to disassemble anyway
                return True, "Binary file detected, attempting disassembly"
    except Exception as e:
        return False, f"Cannot read file: {str(e)}"


def disassemble_exe(exe_path, output_path):
    """Disassemble .exe file to .asm using disassemble.sh"""
    bash_path = None
    result = None
    
    try:
        # Validate the executable first
        is_valid, msg = validate_exe_file(exe_path)
        if not is_valid:
            return False, msg
        
        # Find bash executable
        bash_path = find_bash()
        if bash_path is None:
            return False, (
                "WSL not found on Windows!\n\n"
                "To use this tool on Windows, you need WSL (Windows Subsystem for Linux):\n"
                "1. Open PowerShell as Administrator\n"
                "2. Run: wsl --install\n"
                "3. Restart your computer\n"
                "4. In WSL, run: sudo apt update && sudo apt install binutils\n\n"
                "Alternatively, run this tool directly in a Linux environment."
            )
        
        # Check if objdump is available
        if not check_objdump_available(bash_path):
            if bash_path == 'wsl':
                return False, (
                    "objdump not found in WSL!\n\n"
                    "Please install binutils in WSL:\n"
                    "1. Open WSL terminal\n"
                    "2. Run: sudo apt update\n"
                    "3. Run: sudo apt install binutils\n"
                )
            else:
                return False, (
                    "objdump not found!\n\n"
                    "Please install binutils:\n"
                    "  - Ubuntu/Debian: sudo apt install binutils\n"
                    "  - Fedora/RHEL: sudo dnf install binutils\n"
                    "  - Arch: sudo pacman -S binutils\n"
                )
        
        # Get the directory where streamlit_app.py is located
        script_dir = Path(__file__).parent
        disasm_script = script_dir / 'disassemble.sh'
        
        # Check if disassemble.sh exists
        if not disasm_script.exists():
            return False, f"disassemble.sh not found at {disasm_script}"
        
        # Prepare paths based on environment
        if bash_path == 'wsl':
            # Convert Windows paths to WSL paths
            wsl_exe_path = windows_path_to_wsl(exe_path)
            wsl_output_path = windows_path_to_wsl(output_path)
            wsl_script_path = windows_path_to_wsl(disasm_script)
            
            # Run disassembly in WSL
            # Use sed to strip Windows line endings (\r) before executing
            cmd_str = f"sed 's/\\r$//' '{wsl_script_path}' | bash -s '{wsl_exe_path}' '{wsl_output_path}'"
            cmd = ['wsl', 'bash', '-c', cmd_str]
        else:
            # Native Linux/Mac
            cmd = [
                bash_path,
                str(disasm_script),
                str(exe_path),
                str(output_path)
            ]
        
        # Run disassembly with robust error handling
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace invalid characters instead of crashing
                cwd=str(script_dir) if bash_path != 'wsl' else None,
                timeout=60  # 60 second timeout
            )
        except subprocess.TimeoutExpired:
            return False, "Disassembly timed out (>60s). File may be too large or complex."
        except UnicodeDecodeError as e:
            return False, f"Encoding error while reading disassembly output: {str(e)}"
        except Exception as e:
            return False, f"Failed to run disassembly script: {str(e)}"
        
        # Check if output file was created and has content
        if Path(output_path).exists() and Path(output_path).stat().st_size > 100:
            return True, "Disassembly successful" + (" (via WSL)" if bash_path == 'wsl' else "")
        elif result and result.returncode != 0:
            # Provide detailed error message
            error_msg = ""
            if result.stderr:
                error_msg = result.stderr.strip()
            elif result.stdout:
                error_msg = result.stdout.strip()
            else:
                error_msg = "Unknown error (no output)"
            
            # Safe check for objdump error
            error_msg_lower = error_msg.lower() if error_msg else ""
            
            if "objdump" in error_msg_lower or "command not found" in error_msg_lower:
                if bash_path == 'wsl':
                    return False, (
                        "objdump not found in WSL!\n\n"
                        "Install it with: wsl sudo apt install binutils"
                    )
                else:
                    return False, (
                        "objdump not found!\n\n"
                        "Install binutils: sudo apt install binutils"
                    )
            elif "no such file" in error_msg_lower:
                return False, f"File access error: {error_msg[:300]}"
            elif error_msg:
                return False, f"Disassembly failed:\n{error_msg[:500]}"
            else:
                return False, "Disassembly failed with no error message"
        else:
            # File doesn't exist or is too small
            if not Path(output_path).exists():
                return False, "Disassembly produced no output file. The executable may be invalid or corrupted."
            else:
                return False, "Disassembly produced empty or invalid output. The file may not be a valid executable."
    
    except FileNotFoundError as e:
        return False, f"File not found: {str(e)}"
    except PermissionError as e:
        return False, f"Permission denied: {str(e)}"
    except Exception as e:
        # Catch-all for any other errors
        error_details = f"Error during disassembly: {type(e).__name__}: {str(e)}"
        if bash_path:
            error_details += f"\nBash path: {bash_path}"
        return False, error_details


def run_prediction(asm_path):
    """Run malware prediction using predict.py"""
    try:
        # Validate ASM file exists and is readable
        if not Path(asm_path).exists():
            return None, f"ASM file not found: {asm_path}"
        
        if Path(asm_path).stat().st_size == 0:
            return None, "ASM file is empty"
        
        # Try to read the file to check for encoding issues
        try:
            with open(asm_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(100)  # Read first 100 chars to verify
                if not content.strip():
                    return None, "ASM file appears to be empty or invalid"
        except Exception as e:
            return None, f"Cannot read ASM file: {str(e)}"
        
        predictor = MalwarePredictor()
        
        # Load model
        try:
            if not predictor.load_model():
                return None, "Failed to load ML model. Please train the model first using: python data/models/train_model.py"
        except FileNotFoundError as e:
            return None, f"ML model files not found: {str(e)}\nPlease train the model first using: python data/models/train_model.py"
        except Exception as e:
            return None, f"Error loading ML model: {type(e).__name__}: {str(e)}"
        
        # Get IR file
        try:
            ir_file = predictor.process_sample(asm_path)
            if ir_file is None:
                return None, "Failed to process sample. The MEEF parser may have encountered an error."
        except subprocess.TimeoutExpired:
            return None, "Processing timed out. File may be too large or complex."
        except Exception as e:
            return None, f"Error processing sample: {type(e).__name__}: {str(e)}"
        
        # Extract features
        try:
            features = predictor.extract_features(ir_file)
            if features is None:
                return None, "Failed to extract features from IR file"
        except KeyError as e:
            return None, f"Missing expected feature in IR file: {str(e)}"
        except Exception as e:
            return None, f"Error extracting features: {type(e).__name__}: {str(e)}"
        
        # Make prediction
        try:
            prediction, probability = predictor.predict(features)
            
            # Get explanation for the prediction
            explanation = predictor.explain_prediction(features)
            
            result = {
                'prediction': int(prediction),
                'is_malware': bool(prediction == 1),
                'malware_prob': float(probability[1]),
                'benign_prob': float(probability[0]),
                'confidence': float(max(probability)),
                'explanation': explanation
            }
            
            return result, "Prediction successful"
        except Exception as e:
            return None, f"Error during prediction: {type(e).__name__}: {str(e)}"
    
    except FileNotFoundError as e:
        if "model" in str(e).lower():
            return None, "ML model not found. Please train the model first using: python data/models/train_model.py"
        return None, f"File not found: {str(e)}"
    except PermissionError as e:
        return None, f"Permission denied: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error during prediction: {type(e).__name__}: {str(e)}"


def display_results(result):
    """Display prediction results with nice formatting"""
    is_malware = result['is_malware']
    malware_prob = result['malware_prob']
    benign_prob = result['benign_prob']
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        if is_malware:
            st.markdown(f"""
                <div class='result-box malicious'>
                    <h2 style='color: #ff4444; text-align: center;'>🚨 MALICIOUS DETECTED</h2>
                    <p style='text-align: center; font-size: 1.5rem;'>
                        Confidence: <strong>{malware_prob*100:.2f}%</strong>
                    </p>
                </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
                <div class='result-box benign'>
                    <h2 style='color: #44aa44; text-align: center;'>✅ BENIGN DETECTED</h2>
                    <p style='text-align: center; font-size: 1.5rem;'>
                        Confidence: <strong>{benign_prob*100:.2f}%</strong>
                    </p>
                </div>
            """, unsafe_allow_html=True)
    
    # Detailed probabilities
    st.markdown("### Detailed Analysis")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Malware Probability", f"{malware_prob*100:.2f}%")
    with col2:
        st.metric("Benign Probability", f"{benign_prob*100:.2f}%")
    st.progress(malware_prob, text=f"Malware: {malware_prob*100:.1f}%")
    st.progress(benign_prob, text=f"Benign: {benign_prob*100:.1f}%")

    # Risk level
    if malware_prob >= 0.9:
        risk = "🔴 CRITICAL"
        risk_color = "#ff0000"
    elif malware_prob >= 0.7:
        risk = "🟠 HIGH"
        risk_color = "#ff6600"
    elif malware_prob >= 0.5:
        risk = "🟡 MEDIUM"
        risk_color = "#ffaa00"
    else:
        risk = "🟢 LOW"
        risk_color = "#00cc00"
    
    st.markdown(f"""
        <div style='text-align: center; padding: 1rem; font-size: 1.5rem; margin-top: 1rem;'>
            <strong>Risk Level:</strong> <span style='color: {risk_color}; font-weight: bold;'>{risk}</span>
        </div>
    """, unsafe_allow_html=True)

    # Threat Analysis / Indicators
    if 'explanation' in result and result['explanation']:
        st.markdown("---")
        st.subheader("🔍 Threat Indicators")
        
        if is_malware:
            st.warning("The following suspicious patterns were detected:")
        else:
            st.info("Key features observed:")
            
        for item in result['explanation']:
            desc = item['description']
            # Calculate a simple relevance score for display (0-100%)
            # Heuristic: importance is usually < 0.1, value varies. 
            relevance = min(1.0, item['score'] * 10)
            
            col_a, col_b = st.columns([3, 1])
            with col_a:
                st.markdown(f"**{desc}**")
                st.caption(f"Technical Feature: `{item['name']}`")
            with col_b:
                st.progress(relevance) # Visual indicator of contribution


def main():
    """Main Streamlit application"""
    setup_page()
    display_header()
    
    # Sidebar
    with st.sidebar:
        st.header("ℹ️ About")
        st.markdown("""
            This tool analyzes executable files and assembly code to detect malware using machine learning.
            
            **Workflow:**
            1. Upload .exe or .asm file
            2. Validate/Convert to ASM
            3. Extract features
            4. ML prediction
            
            **Supported formats:**
            - `.exe` (Windows executables)
            - `.asm` (Assembly files)
            - `.dll` (Dynamic libraries)
        """)
        
        st.markdown("---")
        st.markdown("**Powered by MEEF**")
        st.markdown("Machine Learning Enhanced Executable Forensics")
        
        # Diagnostic information
        st.markdown("---")
        st.markdown("**🔧 System Diagnostics**")
        bash_path = find_bash()
        
        if os.name == 'nt':
            # Windows - show WSL status
            if bash_path == 'wsl':
                st.success("✅ WSL detected")
                if check_objdump_available(bash_path):
                    st.success("✅ objdump available in WSL")
                else:
                    st.error("❌ objdump not found in WSL")
                    st.caption("Run in WSL: sudo apt install binutils")
            else:
                st.error("❌ WSL not found")
                st.caption("Install WSL to analyze .exe files")
                with st.expander("How to install WSL"):
                    st.code("""# In PowerShell (as Administrator):
wsl --install

# After restart, in WSL:
sudo apt update && sudo apt install binutils""", language="bash")
        else:
            # Linux/Mac - show bash status
            if bash_path:
                st.success("✅ Bash found")
                if check_objdump_available(bash_path):
                    st.success("✅ objdump available")
                else:
                    st.error("❌ objdump not found")
                    st.caption("Install: sudo apt install binutils")
            else:
                st.error("❌ Bash not found")
    
    # Main content
    st.header("📁 Upload File")
    
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=['exe', 'asm', 'dll'],
        help="Upload an executable (.exe, .dll) or assembly (.asm) file"
    )
    
    if uploaded_file is not None:
        # Display file info
        st.success(f"✅ File uploaded: **{uploaded_file.name}** ({uploaded_file.size} bytes)")
        
        # Create temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Save uploaded file
            uploaded_path = temp_path / uploaded_file.name
            with open(uploaded_path, 'wb') as f:
                f.write(uploaded_file.getbuffer())
            
            # Start analysis
            if st.button("🔍 Analyze File", type="primary"):
                with st.spinner("Analyzing file..."):
                    
                    # Progress tracking
                    progress_bar = st.progress(0, text="Starting analysis...")
                    status_container = st.empty()
                    
                    # Step 1: Validate/Convert to ASM
                    status_container.info("**Step 1/3:** Validating file format...")
                    progress_bar.progress(10, text="Step 1/3: Validating file format...")
                    
                    file_ext = uploaded_path.suffix.lower()
                    asm_path = uploaded_path
                    
                    if file_ext == '.asm':
                        # Validate ASM file
                        is_valid, msg = validate_asm_file(uploaded_path)
                        if is_valid:
                            status_container.success(f"✅ {msg}")
                        else:
                            status_container.error(f"❌ {msg}")
                            st.stop()
                    
                    elif file_ext in ['.exe', '.dll']:
                        # Need to disassemble
                        status_container.info("**Step 1/3:** Converting to assembly...")
                        progress_bar.progress(20, text="Step 1/3: Disassembling executable...")
                        
                        asm_path = temp_path / (uploaded_path.stem + '.asm')
                        success, msg = disassemble_exe(uploaded_path, asm_path)
                        
                        if success:
                            status_container.success(f"✅ {msg}")
                        else:
                            status_container.error(f"❌ Disassembly Failed")
                            st.error(msg)
                            
                            # Show helpful tips based on error
                            if "Git Bash not found" in msg or "bash" in msg.lower():
                                st.info("💡 **Tip:** Check the System Diagnostics in the sidebar to see if Bash is detected")
                            elif "objdump" in msg.lower():
                                st.info("💡 **Tip:** You need objdump (binutils) installed to disassemble executables")
                            elif "empty or invalid output" in msg:
                                st.warning("⚠️ **Possible causes:**\n- File may be packed/encrypted\n- File may be corrupted\n- File may not be a standard PE/ELF executable")
                            
                            st.stop()
                    
                    else:
                        status_container.error(f"❌ Unsupported file type: {file_ext}")
                        st.stop()
                    
                    progress_bar.progress(40, text="Step 1/3: Complete ✅")
                    
                    # Step 2: Show ASM preview
                    status_container.info("**Step 2/3:** Analyzing assembly code...")
                    progress_bar.progress(50, text="Step 2/3: Analyzing assembly code...")
                    
                    with st.expander("📄 View Assembly Code Preview"):
                        try:
                            with open(asm_path, 'r') as f:
                                asm_content = f.read()
                                lines = asm_content.split('\n')
                                st.code('\n'.join(lines[:50]), language='asm')
                                if len(lines) > 50:
                                    st.info(f"Showing first 50 lines of {len(lines)} total lines")
                        except Exception as e:
                            st.warning(f"Could not preview file: {e}")
                    
                    progress_bar.progress(60, text="Step 2/3: Complete ✅")
                    
                    # Step 3: Run prediction
                    status_container.info("**Step 3/3:** Running malware detection...")
                    progress_bar.progress(70, text="Step 3/3: Running ML prediction...")
                    
                    result, msg = run_prediction(asm_path)
                    
                    if result is None:
                        status_container.error(f"❌ {msg}")
                        if "train the model" in msg:
                            st.error("**Action Required:** Please train the ML model first")
                            st.code("python3 data/models/train_model.py", language='bash')
                        st.stop()
                    
                    progress_bar.progress(100, text="Analysis complete! ✅")
                    status_container.success("✅ Analysis complete!")
                    
                    # Display results
                    st.markdown("---")
                    st.header("📊 Results")
                    display_results(result)
                    
                    # Download option for ASM file
                    if file_ext in ['.exe', '.dll']:
                        st.markdown("---")
                        st.subheader("💾 Download Disassembled File")
                        with open(asm_path, 'r') as f:
                            st.download_button(
                                label="Download .asm file",
                                data=f.read(),
                                file_name=asm_path.name,
                                mime="text/plain"
                            )
    
    else:
        # Show instructions when no file uploaded
        st.info("""
            👆 **Upload a file above to get started**
            
            The analyzer will:
            - Validate or convert your file to assembly format
            - Extract behavioral and structural features
            - Use machine learning to predict if it's malware
            - Show detailed confidence scores and risk levels
        """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
        <div style='text-align: center; color: #888; padding: 1rem;'>
            <small>MEEF Malware Detector | Built with Streamlit | For educational purposes only</small>
        </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
