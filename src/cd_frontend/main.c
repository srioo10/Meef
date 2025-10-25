// main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cd_context.h"

/* parser symbols from Bison */
int yyparse(void);
extern FILE *yyin;
extern CDContext global_ctx; /* defined here */
extern void semantic_analyze(CDContext *ctx);
extern void write_ir_json(CDContext *ctx, const char *outpath);

/* define global context */
CDContext global_ctx;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <disasm.txt> [out.json]\n", argv[0]);
        return 1;
    }
    const char *infile = argv[1];
    const char *outfile = (argc >= 3) ? argv[2] : "output/sample_ir.json";

    yyin = fopen(infile, "r");
    if (!yyin) {
        perror("fopen");
        return 1;
    }

    ctx_init(&global_ctx, infile);

    /* run parser (lexer will read from yyin) */
    if (yyparse() != 0) {
        fprintf(stderr, "Parsing failed\n");
        fclose(yyin);
        ctx_free(&global_ctx);
        return 1;
    }
    fclose(yyin);

    /* semantic analysis */
    semantic_analyze(&global_ctx);

    /* write IR */
    write_ir_json(&global_ctx, outfile);
    build_cfg(&global_ctx);
    /* cleanup */
    ctx_free(&global_ctx);
    printf("[+] IR written to %s\n", outfile);
    return 0;
}

