#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "parser.tab.h"
#include "cd_context.h"

extern int yyparse(void);
extern FILE *yyin;
CDContext global_ctx;

extern void semantic_analyze(CDContext *ctx);
extern void build_cfg(CDContext *ctx);
extern void write_ir_json(CDContext *ctx, const char *outpath);

// Ensure output directory exists
void ensure_output_dir(const char *filepath) {
    char *path_copy = strdup(filepath);
    char *last_slash = strrchr(path_copy, '/');
    
    if (last_slash) {
        *last_slash = '\0';
        
        // Create directory (ignoring errors if it exists)
        #ifdef _WIN32
        mkdir(path_copy);
        #else
        mkdir(path_copy, 0755);
        #endif
    }
    
    free(path_copy);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <asm_file> [output.json]\n", argv[0]);
        fprintf(stderr, "Example: %s ../../samples/dummy/fake.asm output/fake_ir.json\n", argv[0]);
        return 1;
    }
    
    const char *infile = argv[1];
    const char *outfile = (argc >= 3) ? argv[2] : "output/sample_ir.json";
    
    // Open input file
    yyin = fopen(infile, "r");
    if (!yyin) {
        perror("Error opening input file");
        return 1;
    }
    
    // Initialize context
    ctx_init(&global_ctx, infile);
    
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║        MEEF Compiler Design Front-End (Phase B)         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("[*] Starting lexical & syntax analysis on: %s\n", infile);
    
    // Parse the input
    int parse_result = yyparse();
    fclose(yyin);
    
    if (parse_result != 0) {
        fprintf(stderr, "\n[✗] Parsing failed\n");
        ctx_free(&global_ctx);
        return 1;
    }
    
    printf("[✓] Parsing successful\n");
    printf("[*] Opcodes found: %zu\n", global_ctx.opcodes_len);
    printf("[*] API calls found: %zu\n", global_ctx.apis_len);
    
    // Semantic analysis
    printf("\n[*] Running semantic analysis...\n");
    semantic_analyze(&global_ctx);
    printf("[✓] Semantic analysis complete\n");
    
    // CFG building
    printf("\n[*] Building Control Flow Graph...\n");
    build_cfg(&global_ctx);
    printf("[✓] CFG built: %d blocks, %d edges\n", 
           global_ctx.cfg_num_blocks, 
           global_ctx.cfg_num_edges);
    
    // Generate IR
    printf("\n[*] Generating Intermediate Representation...\n");
    ensure_output_dir(outfile);
    write_ir_json(&global_ctx, outfile);
    printf("[✓] IR written to: %s\n", outfile);
    
    // Summary
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║                    Analysis Summary                      ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ Network Operations    : %s\n", global_ctx.uses_network ? "YES" : "NO ");
    printf("║ File Operations       : %s\n", global_ctx.uses_fileops ? "YES" : "NO ");
    printf("║ Registry Operations   : %s\n", global_ctx.uses_registry ? "YES" : "NO ");
    printf("║ Memory Operations     : %s\n", global_ctx.uses_memory ? "YES" : "NO ");
    printf("║ Code Injection        : %s\n", global_ctx.uses_injection ? "YES" : "NO ");
    printf("║ Cryptography          : %s\n", global_ctx.uses_crypto ? "YES" : "NO ");
    printf("║ Persistence           : %s\n", global_ctx.uses_persist ? "YES" : "NO ");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ CFG Complexity        : %.2f\n", global_ctx.cfg_cyclomatic_complexity);
    printf("║ Branch Density        : %.4f\n", global_ctx.cfg_branch_density);
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    
    ctx_free(&global_ctx);
    printf("[✓] Analysis complete!\n");
    return 0;
}
