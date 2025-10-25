# Makefile for cd_frontend
CC = gcc
BISON = bison
FLEX = flex
CFLAGS = -O2 -g -Wall
LDFLAGS = -lfl

all: meef_parser

parser.tab.c parser.tab.h: parser.y
	$(BISON) -d -o parser.tab.c parser.y

lex.yy.c: lexer.l parser.tab.h
	$(FLEX) -o lex.yy.c lexer.l

meef_parser: parser.tab.c lex.yy.c semantic_analyzer.c ir_generator.c main.c
	$(CC) $(CFLAGS) -o meef_parser parser.tab.c lex.yy.c semantic_analyzer.c ir_generator.c main.c $(LDFLAGS)

clean:
	rm -f meef_parser parser.tab.c parser.tab.h lex.yy.c

