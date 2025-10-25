#include "cd_context.h"
#include <string.h>

void build_cfg(CDContext *ctx) {
    int edges = 0;
    int blocks = 0;
    int branches = 0;
    
    // Analyze opcodes to build CFG metrics
    for (size_t i = 0; i < ctx->opcodes_len; i++) {
        const char *op = ctx->opcodes[i].key;
        int count = ctx->opcodes[i].count;
        
        // Count basic blocks (simplified: each instruction is a potential block)
        blocks += count;
        
        // Branch instructions create edges
        if (strcmp(op, "JMP") == 0 || 
            strcmp(op, "JZ") == 0 || 
            strcmp(op, "JNZ") == 0 ||
            strcmp(op, "JE") == 0 ||
            strcmp(op, "JNE") == 0 ||
            strcmp(op, "JG") == 0 ||
            strcmp(op, "JL") == 0) {
            branches += count;
            edges += count * 2; // conditional branches create 2 edges
        }
        
        // CALL creates edges (call + return)
        if (strcmp(op, "CALL") == 0) {
            edges += count * 2;
        }
        
        // RET creates edge back
        if (strcmp(op, "RET") == 0) {
            edges += count;
        }
        
        // Direct flow (sequential) creates edges
        if (strcmp(op, "MOV") == 0 ||
            strcmp(op, "PUSH") == 0 ||
            strcmp(op, "POP") == 0 ||
            strcmp(op, "ADD") == 0 ||
            strcmp(op, "SUB") == 0 ||
            strcmp(op, "XOR") == 0) {
            edges += count;
        }
    }
    
    ctx->cfg_num_blocks = blocks > 0 ? blocks : 1;
    ctx->cfg_num_edges = edges > 0 ? edges : 0;
    
    // Calculate metrics
    if (ctx->cfg_num_blocks > 0) {
        ctx->cfg_branch_density = (double)branches / ctx->cfg_num_blocks;
    } else {
        ctx->cfg_branch_density = 0.0;
    }
    
    // Cyclomatic complexity: M = E - N + 2P (P=1 for single program)
    ctx->cfg_cyclomatic_complexity = (double)(ctx->cfg_num_edges - ctx->cfg_num_blocks + 2);
    
    // Ensure non-negative complexity
    if (ctx->cfg_cyclomatic_complexity < 1.0) {
        ctx->cfg_cyclomatic_complexity = 1.0;
    }
}
