CC = gcc
CFLAGS = -O2 -g -Wall -Wextra
LDFLAGS = -lfl

TARGET = meef_parser
SOURCES = parser.tab.c lex.yy.c cd_context.c semantic_analyzer.c ir_generator.c cfg_builder.c main.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete!"

parser.tab.c parser.tab.h: parser.y
	@echo "Generating parser..."
	bison -d -o parser.tab.c parser.y

lex.yy.c: lexer.l parser.tab.h
	@echo "Generating lexer..."
	flex -o lex.yy.c lexer.l

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET) parser.tab.c parser.tab.h lex.yy.c $(OBJECTS)
	rm -f output/*.json
	@echo "Clean complete!"

test: $(TARGET)
	@echo "Running test on fake.asm..."
	@mkdir -p output
	./$(TARGET) ../../samples/dummy/fake.asm output/fake_ir.json
	@echo ""
	@echo "Displaying output:"
	@cat output/fake_ir.json

install-deps:
	@echo "Installing dependencies..."
	@echo "Please ensure the following are installed:"
	@echo "  - gcc"
	@echo "  - flex"
	@echo "  - bison"
	@echo "  - make"
	@echo ""
	@echo "On Ubuntu/Debian: sudo apt install gcc flex bison make"
	@echo "On Fedora/RHEL:   sudo dnf install gcc flex bison make"
