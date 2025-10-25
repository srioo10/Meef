// ir_generator.c
#include <stdio.h>
#include <stdlib.h>
#include "cd_context.h"

void write_ir_json(CDContext *ctx, const char *outpath) {
    FILE *f = fopen(outpath, "w");
    if (!f) {
        fprintf(stderr, "Could not open %s for writing\n", outpath);
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"source\": \"%s\",\n", ctx->filename ? ctx->filename : "unknown");
    fprintf(f, "  \"uses_network\": %d,\n", ctx->uses_network);
    fprintf(f, "  \"uses_fileops\": %d,\n", ctx->uses_fileops);
    fprintf(f, "  \"uses_registry\": %d,\n", ctx->uses_registry);
    fprintf(f, "  \"uses_memory\": %d,\n", ctx->uses_memory);
    fprintf(f, "  \"cfg_num_blocks\": %d,\n", ctx->cfg_num_blocks);
    fprintf(f, "  \"cfg_num_edges\": %d,\n", ctx->cfg_num_edges);
    fprintf(f, "  \"cfg_branch_density\": %.3f,\n", ctx->cfg_branch_density);
    fprintf(f, "  \"cfg_cyclomatic_complexity\": %.3f,\n", ctx->cfg_cyclomatic_complexity);


    /* apis */
    fprintf(f, "  \"apis\": {\n");
    for (size_t i=0;i<ctx->apis_len;i++) {
        fprintf(f, "    \"%s\": %d%s\n",
                ctx->apis[i].key,
                ctx->apis[i].count,
                (i+1==ctx->apis_len) ? "" : ",");
    }
    fprintf(f, "  },\n");

    /* opcodes */
    fprintf(f, "  \"opcodes\": {\n");
    for (size_t i=0;i<ctx->opcodes_len;i++) {
        fprintf(f, "    \"%s\": %d%s\n",
                ctx->opcodes[i].key,
                ctx->opcodes[i].count,
                (i+1==ctx->opcodes_len) ? "" : ",");
    }
    fprintf(f, "  }\n");

    fprintf(f, "}\n");
    fclose(f);
}

