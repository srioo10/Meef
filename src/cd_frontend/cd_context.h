#ifndef CD_CONTEXT_H
#define CD_CONTEXT_H

#include <stdlib.h>

// Key-value pair for counting APIs and opcodes
typedef struct {
    char *key;
    int count;
} KeyCount;

// Global context for compiler design analysis
typedef struct {
    char *filename;
    
    // API and opcode tracking
    KeyCount *apis;
    size_t apis_len;
    size_t apis_cap;
    
    KeyCount *opcodes;
    size_t opcodes_len;
    size_t opcodes_cap;
    
    // Semantic analysis flags
    int uses_network;
    int uses_fileops;
    int uses_registry;
    int uses_memory;
    int uses_injection;
    int uses_crypto;
    int uses_persist;
    
    // CFG metrics
    int cfg_num_blocks;
    int cfg_num_edges;
    double cfg_branch_density;
    double cfg_cyclomatic_complexity;
} CDContext;

// Function declarations (implementation in cd_context.c)
void ctx_init(CDContext *ctx, const char *filename);
void ctx_add_api(CDContext *ctx, const char *api);
void ctx_add_opcode(CDContext *ctx, const char *op);
void ctx_free(CDContext *ctx);

#endif // CD_CONTEXT_H
