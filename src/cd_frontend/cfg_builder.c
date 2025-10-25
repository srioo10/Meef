// cfg_builder.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cd_context.h"

/*
    Simplified Control-Flow Graph Builder
    ------------------------------------
    We model a basic block as a sequence of non-branch instructions
    terminated by a branch instruction (CALL, JMP, RET).
    We don't need full addresses — only counts for metrics.
*/

static int is_branch_opcode(const char *op) {
    if (!op) return 0;
    return (strcmp(op,"JMP")==0 ||
            strcmp(op,"CALL")==0 ||
            strcmp(op,"RET")==0 ||
            strcmp(op,"JNZ")==0 ||
            strcmp(op,"JZ")==0 ||
            strcmp(op,"JE")==0 ||
            strcmp(op,"JNE")==0);
}

void build_cfg(CDContext *ctx) {
    if (!ctx) return;
    if (ctx->opcodes_len == 0) {
        ctx->cfg_num_blocks = 0;
        ctx->cfg_num_edges = 0;
        ctx->cfg_branch_density = 0.0;
        ctx->cfg_cyclomatic_complexity = 0.0;
        return;
    }

    int num_blocks = 0;
    int num_edges  = 0;

    int in_block = 0;
    for (size_t i=0;i<ctx->opcodes_len;i++) {
        const char *op = ctx->opcodes[i].key;
        if (!in_block) {
            in_block = 1;
            num_blocks++;
        }

        if (is_branch_opcode(op)) {
            // terminate current block on a branch
            in_block = 0;
            // branch creates one outgoing edge (approx)
            num_edges++;
            // CALL adds one extra edge for return path
            if (strcmp(op,"CALL")==0) num_edges++;
        }
    }

    // simple approximations
    ctx->cfg_num_blocks = num_blocks;
    ctx->cfg_num_edges  = num_edges;
    if (num_blocks > 0)
        ctx->cfg_branch_density = (double)num_edges / (double)num_blocks;
    else
        ctx->cfg_branch_density = 0.0;

    // classical cyclomatic complexity metric: E - N + 2
    ctx->cfg_cyclomatic_complexity =
        (double)(num_edges - num_blocks + 2);

#ifdef DEBUG_CFG
    printf("[CFG] blocks=%d edges=%d density=%.2f complexity=%.2f\n",
           num_blocks, num_edges,
           ctx->cfg_branch_density,
           ctx->cfg_cyclomatic_complexity);
#endif
}

