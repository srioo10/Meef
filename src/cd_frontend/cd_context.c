#include "cd_context.h"
#include <string.h>
#include <stdlib.h>

void ctx_init(CDContext *ctx, const char *filename) {
    ctx->filename = strdup(filename);
    
    ctx->apis_cap = 64;
    ctx->apis = calloc(ctx->apis_cap, sizeof(KeyCount));
    ctx->apis_len = 0;
    
    ctx->opcodes_cap = 64;
    ctx->opcodes = calloc(ctx->opcodes_cap, sizeof(KeyCount));
    ctx->opcodes_len = 0;
    
    ctx->uses_network = 0;
    ctx->uses_fileops = 0;
    ctx->uses_registry = 0;
    ctx->uses_memory = 0;
    ctx->uses_injection = 0;
    ctx->uses_crypto = 0;
    ctx->uses_persist = 0;
    
    ctx->cfg_num_blocks = 0;
    ctx->cfg_num_edges = 0;
    ctx->cfg_branch_density = 0.0;
    ctx->cfg_cyclomatic_complexity = 0.0;
}

void ctx_add_api(CDContext *ctx, const char *api) {
    // Check if API already exists
    for (size_t i = 0; i < ctx->apis_len; i++) {
        if (strcmp(ctx->apis[i].key, api) == 0) {
            ctx->apis[i].count++;
            return;
        }
    }
    
    // Add new API
    if (ctx->apis_len >= ctx->apis_cap) {
        ctx->apis_cap *= 2;
        ctx->apis = realloc(ctx->apis, ctx->apis_cap * sizeof(KeyCount));
    }
    
    ctx->apis[ctx->apis_len].key = strdup(api);
    ctx->apis[ctx->apis_len].count = 1;
    ctx->apis_len++;
}

void ctx_add_opcode(CDContext *ctx, const char *op) {
    // Check if opcode already exists
    for (size_t i = 0; i < ctx->opcodes_len; i++) {
        if (strcmp(ctx->opcodes[i].key, op) == 0) {
            ctx->opcodes[i].count++;
            return;
        }
    }
    
    // Add new opcode
    if (ctx->opcodes_len >= ctx->opcodes_cap) {
        ctx->opcodes_cap *= 2;
        ctx->opcodes = realloc(ctx->opcodes, ctx->opcodes_cap * sizeof(KeyCount));
    }
    
    ctx->opcodes[ctx->opcodes_len].key = strdup(op);
    ctx->opcodes[ctx->opcodes_len].count = 1;
    ctx->opcodes_len++;
}

void ctx_free(CDContext *ctx) {
    free(ctx->filename);
    
    for (size_t i = 0; i < ctx->apis_len; i++) {
        free(ctx->apis[i].key);
    }
    free(ctx->apis);
    
    for (size_t i = 0; i < ctx->opcodes_len; i++) {
        free(ctx->opcodes[i].key);
    }
    free(ctx->opcodes);
}
