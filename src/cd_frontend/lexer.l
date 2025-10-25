%option noyywrap
%option yylineno

%{
#include "parser.tab.h"
#include <string.h>
#include <stdlib.h>
%}

%%

[ \t\r]+                { /* skip whitespace */ }
\n                      { return NEWLINE; }

MOV|CALL|JMP|JNZ|JZ|JE|JNE|JG|JL|PUSH|POP|RET|ADD|SUB|XOR|AND|OR|TEST|CMP|LEA|NOP   { 
    yylval.s = strdup(yytext); 
    return OPCODE; 
}

[A-Za-z_][A-Za-z0-9_]*(A|W)?   { 
    yylval.s = strdup(yytext); 
    return IDENT; 
}

[0-9]+                  { yylval.s = strdup(yytext); return NUMBER; }
0x[0-9A-Fa-f]+          { yylval.s = strdup(yytext); return NUMBER; }

","                     { return COMMA; }
":"                     { return COLON; }

.                       { /* ignore other chars */ }

%%
