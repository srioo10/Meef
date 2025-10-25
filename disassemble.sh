#!/bin/bash
# Quick disassembly helper for MEEF
# Converts .exe/.dll to .asm using objdump

if [ $# -eq 0 ]; then
    echo "Usage: ./disassemble.sh <binary_file> [output.asm]"
    echo ""
    echo "Examples:"
    echo "  ./disassemble.sh calc.exe calc.asm"
    echo "  ./disassemble.sh samples/malicious/trojan.exe samples/malicious/trojan.asm"
    echo ""
    echo "Requires: objdump (install with 'apt install binutils')"
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-${INPUT%.exe}.asm}"

if [ ! -f "$INPUT" ]; then
    echo "✗ File not found: $INPUT"
    exit 1
fi

echo "[*] Disassembling: $INPUT"
echo "[*] Output: $OUTPUT"

# Check if objdump is available
if ! command -v objdump &> /dev/null; then
    echo "✗ objdump not found!"
    echo "Install with: sudo apt install binutils"
    exit 1
fi

# Disassemble
objdump -d -M intel "$INPUT" > "$OUTPUT"

if [ $? -eq 0 ]; then
    echo "[✓] Disassembly complete!"
    echo ""
    
    # Show stats
    LINES=$(wc -l < "$OUTPUT")
    SIZE=$(stat -f%z "$OUTPUT" 2>/dev/null || stat -c%s "$OUTPUT" 2>/dev/null)
    
    echo "📊 Stats:"
    echo "   Lines: $LINES"
    echo "   Size: $(numfmt --to=iec-i --suffix=B $SIZE 2>/dev/null || echo $SIZE bytes)"
    echo ""
    echo "Preview (first 10 lines):"
    head -10 "$OUTPUT"
    echo ""
    echo "Ready to process with: ./meef_parser $OUTPUT output/result_ir.json"
else
    echo "✗ Disassembly failed"
    exit 1
fi
