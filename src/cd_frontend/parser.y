%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cd_context.h"

extern CDContext global_ctx;
void ctx_add_api(CDContext *ctx, const char *api);
void ctx_add_opcode(CDContext *ctx, const char *op);
%}

%union {
    char *s;
}

%token <s> API IDENT OPCODE HEX
%token NEWLINE

%start program

%%

program:
      /* empty */
    | program line
    ;

line:
      stmt NEWLINE    { /* ignore */ }
    | NEWLINE         { /* blank line */ }
    ;

stmt:
      instr
    | call_expr
    | other
    ;

instr:
      OPCODE
      {
          /* record opcode */
          ctx_add_opcode(&global_ctx, $1);
          free($1);
      }
    ;

call_expr:
      OPCODE IDENT   /* e.g., CALL CreateFileA or CALL VirtualAlloc */
      {
          /* If the second token looks like an API, record it */
          ctx_add_opcode(&global_ctx, $1);
          ctx_add_api(&global_ctx, $2);
          free($1);
          free($2);
      }
    | OPCODE API
      {
          ctx_add_opcode(&global_ctx, $1);
          ctx_add_api(&global_ctx, $2);
          free($1);
          free($2);
      }
    ;

other:
      IDENT { /* capture identifiers that might still be relevant */ free($1); }
    | HEX   { free($1); }
    ;

%%

/* error handling */
void yyerror(const char *s) {
    fprintf(stderr, "Parse error: %s\n", s);
}

