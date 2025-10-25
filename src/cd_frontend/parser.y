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
    | IDENT NEWLINE             { 
        // Potential API call or variable
        ctx_add_api(&global_ctx, $1); 
        free($1); 
    }
    | NEWLINE
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
    ;

%%

void yyerror(const char *s) {
    fprintf(stderr, "Parse error at line %d: %s\n", yylineno, s);
}
