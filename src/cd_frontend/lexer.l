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

"//".*                  { /* C++ style comment */ }
";".*                   { /* Assembly comment */ }
"#".*                   { /* Preprocessor/comment */ }

"."[a-zA-Z0-9_]+        { /* Skip assembler directives like .text, .data, .section */ }

MOV|CALL|JMP|JNZ|JZ|JE|JNE|JG|JL|JGE|JLE|JA|JB|JAE|JBE|PUSH|POP|RET|ADD|SUB|XOR|AND|OR|TEST|CMP|LEA|NOP|INT|SYSCALL|LEAVE|ENTER   { 
    yylval.s = strdup(yytext); 
    return OPCODE; 
}

[A-Za-z_][A-Za-z0-9_]*(A|W)?   { 
    yylval.s = strdup(yytext); 
    return IDENT; 
}

[0-9]+                  { yylval.s = strdup(yytext); return NUMBER; }
0x[0-9A-Fa-f]+          { yylval.s = strdup(yytext); return NUMBER; }
[0-9][0-9A-Fa-f]*[hH]   { yylval.s = strdup(yytext); return NUMBER; }

","                     { return COMMA; }
":"                     { return COLON; }
"["                     { /* Skip brackets */ }
"]"                     { /* Skip brackets */ }
"+"                     { /* Skip operators */ }
"-"                     { /* Skip operators */ }
"*"                     { /* Skip operators */ }

.                       { /* ignore other chars */ }

%%
