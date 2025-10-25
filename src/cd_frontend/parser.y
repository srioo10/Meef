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

// Flag to suppress error spam
int error_count = 0;
#define MAX_ERRORS 10
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
        free($1); 
    }
    | OPCODE NEWLINE            { 
        ctx_add_opcode(&global_ctx, $1); 
        free($1); 
    }
    | IDENT COLON NEWLINE       { 
        // Label definition - could track for CFG
        free($1); 
    }
    | IDENT COLON operands NEWLINE { 
        // Label with instruction on same line
        free($1); 
    }
    | IDENT operands NEWLINE    { 
        // Potential API call or instruction without opcode
        ctx_add_api(&global_ctx, $1); 
        free($1); 
    }
    | IDENT NEWLINE             { 
        // Potential API call or variable
        ctx_add_api(&global_ctx, $1); 
        free($1); 
    }
    | NUMBER NEWLINE            {
        // Raw number/address
        free($1);
    }
    | NEWLINE
    | error NEWLINE             {
        // Error recovery - skip to next line
        yyerrok;
    }
    ;

operands
    : operand
    | operands COMMA operand
    ;

operand
    : IDENT                     { 
        // This could be an API call in CALL instructions
        ctx_add_api(&global_ctx, $1); 
        free($1); 
    }
    | NUMBER                    { free($1); }
    | IDENT COLON IDENT         {
        // Segment:offset notation
        ctx_add_api(&global_ctx, $1);
        ctx_add_api(&global_ctx, $3);
        free($1);
        free($3);
    }
    ;

%%

void yyerror(const char *s) {
    error_count++;
    if (error_count <= MAX_ERRORS) {
        fprintf(stderr, "Parse error at line %d: %s\n", yylineno, s);
    }
    if (error_count == MAX_ERRORS) {
        fprintf(stderr, "(Suppressing further errors...)\n");
    }
}
