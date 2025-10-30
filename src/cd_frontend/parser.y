%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cd_context.h"

extern int yylex(void);
extern FILE *yyin;
extern int yylineno;
void yyerror(const char *s);
extern CDContext global_ctx;

// Track if we're in a CALL instruction
static int in_call = 0;
static char *last_opcode = NULL;
%}

%union { 
    char *s; 
}

%token <s> OPCODE
%token <s> IDENT
%token <s> NUMBER
%token NEWLINE
%token COMMA
%token COLON

%%

program
    : /* empty */
    | program line
    ;

line
    : OPCODE operands NEWLINE   { 
        ctx_add_opcode(&global_ctx, $1);
        
        // Set flag if this is a CALL
        if (strcmp($1, "CALL") == 0) {
            in_call = 1;
        } else {
            in_call = 0;
        }
        
        free($1);
    }
    | OPCODE NEWLINE            { 
        ctx_add_opcode(&global_ctx, $1);
        in_call = 0;
        free($1); 
    }
    | IDENT COLON NEWLINE       { 
        // Label definition
        in_call = 0;
        free($1); 
    }
    | NEWLINE                   {
        in_call = 0;
    }
    | error NEWLINE             {
        in_call = 0;
        yyerrok;
    }
    ;

operands
    : operand
    | operands COMMA operand
    ;

operand
    : IDENT                     { 
        // ONLY extract as API if:
        // 1. We're in a CALL instruction
        // 2. It's not a register name
        // 3. It's not a memory operand keyword
        
        if (in_call) {
            // Check if it's NOT a register
            if (strcmp($1, "EAX") != 0 && strcmp($1, "EBX") != 0 && 
                strcmp($1, "ECX") != 0 && strcmp($1, "EDX") != 0 &&
                strcmp($1, "ESI") != 0 && strcmp($1, "EDI") != 0 &&
                strcmp($1, "EBP") != 0 && strcmp($1, "ESP") != 0 &&
                strcmp($1, "RAX") != 0 && strcmp($1, "RBX") != 0 &&
                strcmp($1, "RCX") != 0 && strcmp($1, "RDX") != 0 &&
                strcmp($1, "RSI") != 0 && strcmp($1, "RDI") != 0 &&
                strcmp($1, "RBP") != 0 && strcmp($1, "RSP") != 0 &&
                strcmp($1, "R8") != 0 && strcmp($1, "R9") != 0 &&
                strcmp($1, "R10") != 0 && strcmp($1, "R11") != 0 &&
                strcmp($1, "R12") != 0 && strcmp($1, "R13") != 0 &&
                strcmp($1, "R14") != 0 && strcmp($1, "R15") != 0 &&
                strcmp($1, "R8D") != 0 && strcmp($1, "R9D") != 0 &&
                strcmp($1, "R10D") != 0 && strcmp($1, "R11D") != 0 &&
                strcmp($1, "R14D") != 0 &&
                strcmp($1, "QWORD") != 0 && strcmp($1, "DWORD") != 0 &&
                strcmp($1, "WORD") != 0 && strcmp($1, "BYTE") != 0 &&
                strcmp($1, "PTR") != 0 && strcmp($1, "RIP") != 0) {
                
                // This looks like a real API name or function
                ctx_add_api(&global_ctx, $1);
            }
        }
        // Don't add registers/keywords as APIs
        
        free($1); 
    }
    | NUMBER                    { 
        free($1); 
    }
    ;

%%

void yyerror(const char *s) {
    if (yylineno <= 10) {  // Only show first few errors
        fprintf(stderr, "Parse error at line %d: %s\n", yylineno, s);
    }
}
