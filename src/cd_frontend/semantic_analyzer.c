#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "cd_context.h"

// Check if string looks like a hex address
int is_address(const char *str) {
    if (!str || strlen(str) == 0) return 0;
    
    // Check for 0x prefix
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        for (size_t i = 2; i < strlen(str); i++) {
            if (!isxdigit(str[i])) return 0;
        }
        return strlen(str) > 4;  // Must be reasonable length
    }
    
    // Check if all hex digits (addresses without 0x)
    if (strlen(str) >= 6) {  // Addresses are typically 6+ hex digits
        for (size_t i = 0; i < strlen(str); i++) {
            if (!isxdigit(str[i])) return 0;
        }
        return 1;
    }
    
    return 0;
}

void semantic_analyze(CDContext *ctx) {
    int has_real_apis = 0;
    int total_calls = 0;
    
    // Count CALL instructions
    for (size_t i = 0; i < ctx->opcodes_len; i++) {
        if (strcmp(ctx->opcodes[i].key, "CALL") == 0) {
            total_calls = ctx->opcodes[i].count;
            break;
        }
    }
    
    // METHOD 1: API Name-Based Detection (for non-stripped binaries)
    for (size_t i = 0; i < ctx->apis_len; i++) {
        const char *api = ctx->apis[i].key;
        
        // Skip addresses
        if (is_address(api)) continue;
        
        // Skip single-char or very short strings
        if (strlen(api) < 4) continue;
        
        has_real_apis = 1;
        
        // Network operations
        if (strcasestr(api, "Internet") || strcasestr(api, "Http") || 
            strcasestr(api, "send") || strcasestr(api, "recv") ||
            strcasestr(api, "socket") || strcasestr(api, "connect") ||
            strcasestr(api, "WSA") || strcasestr(api, "WinHttp") ||
            strcasestr(api, "URL") || strcasestr(api, "Download")) {
            ctx->uses_network = 1;
        }
        
        // File operations
        if (strcasestr(api, "File") || strcasestr(api, "Read") ||
            strcasestr(api, "Write") || strcasestr(api, "Open") ||
            strcasestr(api, "Close") || strcasestr(api, "Find") ||
            strcasestr(api, "Delete") || strcasestr(api, "Copy") ||
            strcasestr(api, "Move")) {
            ctx->uses_fileops = 1;
        }
        
        // Registry operations
        if (strcasestr(api, "Reg") || strcasestr(api, "Key")) {
            ctx->uses_registry = 1;
        }
        
        // Memory operations
        if (strcasestr(api, "Alloc") || strcasestr(api, "Virtual") ||
            strcasestr(api, "Heap") || strcasestr(api, "Memory") ||
            strcasestr(api, "Process")) {
            ctx->uses_memory = 1;
        }
        
        // Injection
        if (strcasestr(api, "Thread") || strcasestr(api, "Inject") ||
            strcasestr(api, "Remote") || strcasestr(api, "Hook")) {
            ctx->uses_injection = 1;
        }
        
        // Crypto
        if (strcasestr(api, "Crypt") || strcasestr(api, "Encrypt") ||
            strcasestr(api, "Hash") || strcasestr(api, "Cipher")) {
            ctx->uses_crypto = 1;
        }
        
        // Persistence
        if (strcasestr(api, "Service") || strcasestr(api, "Startup") ||
            strcasestr(api, "Execute") || strcasestr(api, "Create")) {
            ctx->uses_persist = 1;
        }
    }
    
    // METHOD 2: HEURISTIC Detection (for stripped binaries)
    // If we have NO real API names, use code patterns
    
    if (!has_real_apis || ctx->apis_len < 5) {
        // This is likely a stripped binary
        // Use statistical heuristics
        
        int xor_count = 0;
        int test_count = 0;
        int cmp_count = 0;
        int mov_count = 0;
        int push_count = 0;
        
        for (size_t i = 0; i < ctx->opcodes_len; i++) {
            const char *op = ctx->opcodes[i].key;
            int count = ctx->opcodes[i].count;
            
            if (strcmp(op, "XOR") == 0) xor_count = count;
            if (strcmp(op, "TEST") == 0) test_count = count;
            if (strcmp(op, "CMP") == 0) cmp_count = count;
            if (strcmp(op, "MOV") == 0) mov_count = count;
            if (strcmp(op, "PUSH") == 0) push_count = count;
        }
        
        // Heuristic 1: High XOR usage suggests crypto/obfuscation
        if (xor_count > 20) {
            ctx->uses_crypto = 1;
        }
        
        // Heuristic 2: Many CALLs suggest API usage
        if (total_calls > 10) {
            // Assume file and memory operations (common in all programs)
            ctx->uses_fileops = 1;
            ctx->uses_memory = 1;
            
            // If also high complexity, assume network/injection
            if (ctx->cfg_cyclomatic_complexity > 50) {
                ctx->uses_network = 1;
            }
            
            if (ctx->cfg_cyclomatic_complexity > 100) {
                ctx->uses_injection = 1;
            }
        }
        
        // Heuristic 3: High branching density suggests complex malware
        if (ctx->cfg_branch_density > 0.5 && total_calls > 20) {
            ctx->uses_network = 1;
            ctx->uses_persist = 1;
        }
        
        // Heuristic 4: Many PUSH/POP with many CALLs = API usage
        if (push_count > 30 && total_calls > 15) {
            ctx->uses_registry = 1;
            ctx->uses_persist = 1;
        }
        
        // Heuristic 5: Very high instruction count = likely malware
        if (mov_count > 100 && total_calls > 25) {
            ctx->uses_injection = 1;
        }
    }
    
    // METHOD 3: CFG-Based Detection
    // High complexity often indicates malicious behavior
    
    if (ctx->cfg_cyclomatic_complexity > 150) {
        // Very complex code - likely malware with obfuscation
        ctx->uses_crypto = 1;
        ctx->uses_injection = 1;
    }
    
    if (ctx->cfg_num_blocks > 200 && ctx->cfg_branch_density > 0.3) {
        // Large, highly branched code - suspicious
        ctx->uses_network = 1;
        ctx->uses_fileops = 1;
        ctx->uses_memory = 1;
    }
}
