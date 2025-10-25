// cd_context.h
#ifndef CD_CONTEXT_H
#define CD_CONTEXT_H

#include <stddef.h>

typedef struct {
    char *key;
    int count;
} KeyCount;

typedef struct {
    char *filename;         // source filename (for IR metadata)
    KeyCount *apis;         // dynamic array of api counts
    size_t apis_len;
    KeyCount *opcodes;      // dynamic array of opcode counts
    size_t opcodes_len;

    int uses_network;
    int uses_fileops;
    int uses_registry;
    int uses_memory;
   /* --- CFG metrics --- */
    int cfg_num_blocks;
    int cfg_num_edges;
    double cfg_branch_density;
    double cfg_cyclomatic_complexity;

} CDContext;

/* helpers */
void ctx_init(CDContext *ctx, const char *filename);
void ctx_free(CDContext *ctx);
void ctx_add_api(CDContext *ctx, const char *api);
void ctx_add_opcode(CDContext *ctx, const char *op);
void build_cfg(CDContext *ctx);

#endif
