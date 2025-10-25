// semantic_analyzer.c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "cd_context.h"

/* helper: simple substring match (case-insensitive) */
static int contains_substr(const char *s, const char *sub) {
    if (!s || !sub) return 0;
    char *pos = strcasestr(s, sub);
    return (pos != NULL);
}

/* initialize context with defaults */
void ctx_init(CDContext *ctx, const char *filename) {
    ctx->filename = NULL;
    if (filename) {
        ctx->filename = strdup(filename);
    }

    ctx->apis = NULL;
    ctx->apis_len = 0;

    ctx->opcodes = NULL;
    ctx->opcodes_len = 0;

    ctx->uses_network   = 0;
    ctx->uses_fileops   = 0;
    ctx->uses_registry  = 0;
    ctx->uses_memory    = 0;
    ctx->uses_injection = 0;
    ctx->uses_crypto    = 0;
    ctx->uses_persist   = 0;

    /* optional CFG metrics (default = 0) */
    ctx->cfg_num_blocks = 0;
    ctx->cfg_num_edges  = 0;
    ctx->cfg_branch_density = 0.0;
    ctx->cfg_cyclomatic_complexity = 0.0;
}

/* free all dynamic allocations */
void ctx_free(CDContext *ctx) {
    if (!ctx) return;

    if (ctx->filename) free(ctx->filename);

    for (size_t i = 0; i < ctx->apis_len; i++)
        free(ctx->apis[i].key);
    free(ctx->apis);

    for (size_t i = 0; i < ctx->opcodes_len; i++)
        free(ctx->opcodes[i].key);
    free(ctx->opcodes);

    /* reset lengths */
    ctx->apis_len = 0;
    ctx->opcodes_len = 0;
}

/* add or increment key in KeyCount array (common helper) */
static void upsert_keycount(KeyCount **arr, size_t *len, const char *key) {
    if (!key || !arr || !len) return;
    for (size_t i = 0; i < *len; i++) {
        if (strcmp((*arr)[i].key, key) == 0) {
            (*arr)[i].count++;
            return;
        }
    }
    /* add new key */
    *arr = realloc(*arr, ((*len) + 1) * sizeof(KeyCount));
    if (!*arr) return;
    (*arr)[*len].key = strdup(key);
    (*arr)[*len].count = 1;
    (*len)++;
}

/* add API call occurrence */
void ctx_add_api(CDContext *ctx, const char *api) {
    if (!ctx || !api) return;
    upsert_keycount(&ctx->apis, &ctx->apis_len, api);
}

/* add opcode occurrence */
void ctx_add_opcode(CDContext *ctx, const char *op) {
    if (!ctx || !op) return;
    upsert_keycount(&ctx->opcodes, &ctx->opcodes_len, op);
}

/* === SEMANTIC ANALYSIS ===
   In a real compiler, this is the stage that derives meaning.
   Here, we use heuristic API name patterns to detect behavior categories.
*/
void semantic_analyze(CDContext *ctx) {
    if (!ctx) return;

    for (size_t i = 0; i < ctx->apis_len; i++) {
        const char *api = ctx->apis[i].key;

        /* 1️⃣ Network-related */
        if (contains_substr(api, "Internet") ||
            contains_substr(api, "Http") ||
            contains_substr(api, "WinSock") ||
            contains_substr(api, "WSA") ||
            contains_substr(api, "send") ||
            contains_substr(api, "recv") ||
            contains_substr(api, "connect")) {
            ctx->uses_network = 1;
        }

        /* 2️⃣ File operations */
        if (contains_substr(api, "CreateFile") ||
            contains_substr(api, "WriteFile") ||
            contains_substr(api, "DeleteFile") ||
            contains_substr(api, "CopyFile") ||
            contains_substr(api, "ReadFile") ||
            contains_substr(api, "MoveFile")) {
            ctx->uses_fileops = 1;
        }

        /* 3️⃣ Registry operations */
        if (contains_substr(api, "RegSet") ||
            contains_substr(api, "RegCreate") ||
            contains_substr(api, "RegOpen") ||
            contains_substr(api, "RegDelete")) {
            ctx->uses_registry = 1;
        }

        /* 4️⃣ Memory operations / injection */
        if (contains_substr(api, "VirtualAlloc") ||
            contains_substr(api, "WriteProcessMemory") ||
            contains_substr(api, "CreateRemoteThread") ||
            contains_substr(api, "NtAllocateVirtualMemory")) {
            ctx->uses_memory = 1;
            ctx->uses_injection = 1;
        }

        /* 5️⃣ Persistence mechanisms */
        if (contains_substr(api, "CreateService") ||
            contains_substr(api, "SetWindowsHook") ||
            contains_substr(api, "ShellExecute") ||
            contains_substr(api, "Startup") ||
            contains_substr(api, "ScheduleService")) {
            ctx->uses_persist = 1;
        }

        /* 6️⃣ Cryptography / encoding */
        if (contains_substr(api, "Crypt") ||
            contains_substr(api, "Encrypt") ||
            contains_substr(api, "Decrypt") ||
            contains_substr(api, "Base64")) {
            ctx->uses_crypto = 1;
        }
    }

    /* optional: opcode-based heuristics */
    for (size_t j = 0; j < ctx->opcodes_len; j++) {
        const char *op = ctx->opcodes[j].key;
        if (strcmp(op, "JMP") == 0 || strcmp(op, "CALL") == 0) {
            /* could be used later for CFG metrics */
        }
    }
}

/* print context summary (for debugging) */
void ctx_debug_print(CDContext *ctx) {
    printf("=== SEMANTIC SUMMARY ===\n");
    printf("Network: %d | FileOps: %d | Registry: %d | Memory: %d | Inject: %d | Persist: %d | Crypto: %d\n",
           ctx->uses_network, ctx->uses_fileops, ctx->uses_registry,
           ctx->uses_memory, ctx->uses_injection, ctx->uses_persist, ctx->uses_crypto);

    printf("APIs recorded: %zu\n", ctx->apis_len);
    for (size_t i = 0; i < ctx->apis_len; i++) {
        printf("  %s (%d)\n", ctx->apis[i].key, ctx->apis[i].count);
    }

    printf("Opcodes recorded: %zu\n", ctx->opcodes_len);
    for (size_t i = 0; i < ctx->opcodes_len; i++) {
        printf("  %s (%d)\n", ctx->opcodes[i].key, ctx->opcodes[i].count);
    }
}

