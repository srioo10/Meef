#include <string.h>
#include <strings.h>
#include "cd_context.h"

void semantic_analyze(CDContext *ctx) {
    // Analyze API calls to detect behavioral patterns
    for (size_t i = 0; i < ctx->apis_len; i++) {
        const char *api = ctx->apis[i].key;
        
        // Network operations
        if (strcasestr(api, "Internet") || 
            strcasestr(api, "Http") || 
            strcasestr(api, "send") ||
            strcasestr(api, "recv") ||
            strcasestr(api, "socket") ||
            strcasestr(api, "connect") ||
            strcasestr(api, "WSA")) {
            ctx->uses_network = 1;
        }
        
        // File operations
        if (strcasestr(api, "CreateFile") || 
            strcasestr(api, "WriteFile") ||
            strcasestr(api, "ReadFile") ||
            strcasestr(api, "DeleteFile") ||
            strcasestr(api, "MoveFile") ||
            strcasestr(api, "CopyFile")) {
            ctx->uses_fileops = 1;
        }
        
        // Registry operations
        if (strcasestr(api, "Reg") ||
            strcasestr(api, "RegOpenKey") ||
            strcasestr(api, "RegSetValue") ||
            strcasestr(api, "RegCreateKey")) {
            ctx->uses_registry = 1;
        }
        
        // Memory operations
        if (strcasestr(api, "VirtualAlloc") || 
            strcasestr(api, "WriteProcessMemory") ||
            strcasestr(api, "ReadProcessMemory") ||
            strcasestr(api, "VirtualProtect") ||
            strcasestr(api, "HeapAlloc")) {
            ctx->uses_memory = 1;
        }
        
        // Code injection
        if (strcasestr(api, "CreateRemoteThread") ||
            strcasestr(api, "NtCreateThreadEx") ||
            strcasestr(api, "QueueUserAPC") ||
            strcasestr(api, "SetWindowsHook")) {
            ctx->uses_injection = 1;
        }
        
        // Cryptography
        if (strcasestr(api, "Crypt") || 
            strcasestr(api, "Encrypt") ||
            strcasestr(api, "Decrypt") ||
            strcasestr(api, "Hash")) {
            ctx->uses_crypto = 1;
        }
        
        // Persistence
        if (strcasestr(api, "Service") || 
            strcasestr(api, "Startup") ||
            strcasestr(api, "CreateProcess") ||
            strcasestr(api, "ShellExecute") ||
            strcasestr(api, "WinExec")) {
            ctx->uses_persist = 1;
        }
    }
}
