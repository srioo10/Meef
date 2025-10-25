%option noyywrap
%{
#include "parser.tab.h"
#include <string.h>
#include <stdlib.h>

/* yylval.s is used to pass strings to parser */
%}

ALPHA      [A-Za-z]
ALNUM      [A-Za-z0-9_]
HEXCONST   0x[0-9A-Fa-f]+

%%
[ \t\r]+                { /* skip whitespace */ }
\n                      { return NEWLINE; }

/* common opcodes (simple) */
"\<MOV\>"               { yylval.s = strdup(yytext); return OPCODE; }
"\<CALL\>"              { yylval.s = strdup(yytext); return OPCODE; }
"\<JMP\>"               { yylval.s = strdup(yytext); return OPCODE; }
"\<PUSH\>"              { yylval.s = strdup(yytext); return OPCODE; }
"\<POP\>"               { yylval.s = strdup(yytext); return OPCODE; }
"\<RET\>"               { yylval.s = strdup(yytext); return OPCODE; }

/* API-like tokens (DLL functions) */
([A-Za-z_][A-Za-z0-9_]*"A")|([A-Za-z_][A-Za-z0-9_]*"W")    {
                            yylval.s = strdup(yytext);
                            return API;
                          }

/* raw identifiers that might be API names or labels */
[A-Za-z_][A-Za-z0-9_]*  {
                            yylval.s = strdup(yytext);
                            return IDENT;
                        }

/* hex constants like 0x401000 */
{HEXCONST}              { yylval.s = strdup(yytext); return HEX; }

/* anything else - treat as token for parser if needed */
.                       { /* ignore other single chars */ }
%%

/* no additional C code here */

