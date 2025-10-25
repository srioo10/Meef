#include <stdio.h>
#include "cd_context.h"

void write_ir_json(CDContext *ctx, const char *outpath) {
    FILE *f = fopen(outpath, "w");
    if (!f) {
        perror("fopen");
        return;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"filename\": \"%s\",\n", ctx->filename);
    
    // Semantic analysis results
    fprintf(f, "  \"behavior\": {\n");
    fprintf(f, "    \"uses_network\": %d,\n", ctx->uses_network);
    fprintf(f, "    \"uses_fileops\": %d,\n", ctx->uses_fileops);
    fprintf(f, "    \"uses_registry\": %d,\n", ctx->uses_registry);
    fprintf(f, "    \"uses_memory\": %d,\n", ctx->uses_memory);
    fprintf(f, "    \"uses_injection\": %d,\n", ctx->uses_injection);
    fprintf(f, "    \"uses_crypto\": %d,\n", ctx->uses_crypto);
    fprintf(f, "    \"uses_persist\": %d\n", ctx->uses_persist);
    fprintf(f, "  },\n");
    
    // CFG metrics
    fprintf(f, "  \"cfg\": {\n");
    fprintf(f, "    \"num_blocks\": %d,\n", ctx->cfg_num_blocks);
    fprintf(f, "    \"num_edges\": %d,\n", ctx->cfg_num_edges);
    fprintf(f, "    \"branch_density\": %.4f,\n", ctx->cfg_branch_density);
    fprintf(f, "    \"cyclomatic_complexity\": %.4f\n", ctx->cfg_cyclomatic_complexity);
    fprintf(f, "  },\n");
    
    // API calls
    fprintf(f, "  \"apis\": [\n");
    for (size_t i = 0; i < ctx->apis_len; i++) {
        fprintf(f, "    {\"name\": \"%s\", \"count\": %d}%s\n",
                ctx->apis[i].key,
                ctx->apis[i].count,
                (i < ctx->apis_len - 1) ? "," : "");
    }
    fprintf(f, "  ],\n");
    
    // Opcodes
    fprintf(f, "  \"opcodes\": [\n");
    for (size_t i = 0; i < ctx->opcodes_len; i++) {
        fprintf(f, "    {\"name\": \"%s\", \"count\": %d}%s\n",
                ctx->opcodes[i].key,
                ctx->opcodes[i].count,
                (i < ctx->opcodes_len - 1) ? "," : "");
    }
    fprintf(f, "  ]\n");
    
    fprintf(f, "}\n");
    fclose(f);
}
