#!/bin/bash
# Enhanced disassembly helper for MEEF
# Converts .exe/.dll to .asm using objdump
# Supports both single files and batch folder processing

print_usage() {
    echo "Usage:"
    echo "  Single file:  ./disassemble.sh <file.exe> [output.asm]"
    echo "  Batch folder: ./disassemble.sh <folder_path>"
    echo ""
    echo "Examples:"
    echo "  ./disassemble.sh calc.exe calc.asm"
    echo "  ./disassemble.sh samples/malicious/trojan.exe"
    echo "  ./disassemble.sh samples/malicious/"
    echo "  ./disassemble.sh samples/malicious/*.exe"
    echo ""
    echo "Requires: objdump (install with 'apt install binutils')"
}

if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

# Check if objdump is available
if ! command -v objdump &> /dev/null; then
    echo "✗ objdump not found!"
    echo "Install with: sudo apt install binutils"
    exit 1
fi

disassemble_file() {
    local INPUT="$1"
    local OUTPUT="$2"
    
    # If no output specified, use input name with .asm extension
    if [ -z "$OUTPUT" ]; then
        OUTPUT="${INPUT%.*}.asm"
    fi
    
    # Check if input file exists
    if [ ! -f "$INPUT" ]; then
        echo "✗ File not found: $INPUT"
        return 1
    fi
    
    echo "[*] Disassembling: $(basename "$INPUT")"
    echo "    Output: $OUTPUT"
    
    # Disassemble
    objdump -d -M intel "$INPUT" > "$OUTPUT" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # Check if output has meaningful content
        LINES=$(wc -l < "$OUTPUT" 2>/dev/null)
        SIZE=$(stat -c%s "$OUTPUT" 2>/dev/null || stat -f%z "$OUTPUT" 2>/dev/null)
        
        if [ "$SIZE" -gt 100 ]; then
            echo "[✓] Success! ($LINES lines, $(numfmt --to=iec-i --suffix=B $SIZE 2>/dev/null || echo $SIZE bytes))"
            return 0
        else
            echo "[✗] Disassembly produced empty output"
            rm -f "$OUTPUT"
            return 1
        fi
    else
        echo "[✗] Disassembly failed"
        rm -f "$OUTPUT"
        return 1
    fi
}

# Main logic
INPUT_PATH="$1"
OUTPUT_PATH="$2"

# Check if input is a directory
if [ -d "$INPUT_PATH" ]; then
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           Batch Disassembly Mode (Folder)               ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "[*] Scanning folder: $INPUT_PATH"
    
    # Find all .exe and .dll files
    FILES=$(find "$INPUT_PATH" -maxdepth 1 -type f \( -iname "*.exe" -o -iname "*.dll" \))
    COUNT=$(echo "$FILES" | grep -c .)
    
    if [ -z "$FILES" ] || [ "$COUNT" -eq 0 ]; then
        echo "[✗] No .exe or .dll files found in $INPUT_PATH"
        exit 1
    fi
    
    echo "[✓] Found $COUNT file(s)"
    echo ""
    
    # Process each file
    SUCCESS=0
    FAILED=0
    
    while IFS= read -r FILE; do
        if [ -n "$FILE" ]; then
            if disassemble_file "$FILE"; then
                ((SUCCESS++))
            else
                ((FAILED++))
            fi
            echo ""
        fi
    done <<< "$FILES"
    
    # Summary
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Disassembly Complete                   ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║ Total files:     $COUNT"
    echo "║ Success:         $SUCCESS"
    echo "║ Failed:          $FAILED"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "[*] ASM files saved in: $INPUT_PATH"
    
elif [ -f "$INPUT_PATH" ]; then
    # Single file mode
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          Single File Disassembly Mode                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    
    if disassemble_file "$INPUT_PATH" "$OUTPUT_PATH"; then
        OUTPUT="${OUTPUT_PATH:-${INPUT_PATH%.*}.asm}"
        echo ""
        echo "📊 Quick Stats:"
        LINES=$(wc -l < "$OUTPUT")
        echo "   Total lines: $LINES"
        echo ""
        echo "Preview (first 10 lines):"
        head -10 "$OUTPUT"
        echo ""
        echo "Ready to process with:"
        echo "  ./src/cd_frontend/meef_parser $OUTPUT output/result_ir.json"
        exit 0
    else
        exit 1
    fi
    
else
    echo "✗ Input not found: $INPUT_PATH"
    echo ""
    print_usage
    exit 1
fi
