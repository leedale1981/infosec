CC = gcc
# _GNU_SOURCE is required for strcasestr()/strcasecmp(); without it they are
# implicitly declared as returning int, which truncates the pointer on 64-bit
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -D_GNU_SOURCE
LDFLAGS = -luuid -lcurl -lcjson

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = .

# Source and object files
# stubs.c is the mock implementation used only by Makefile.quick - including it
# here duplicates every symbol in ai_client.c/analysis.c/vulnerability_analyzer.c
SOURCES = $(filter-out $(SRC_DIR)/stubs.c,$(wildcard $(SRC_DIR)/*.c))
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
TARGET = $(BIN_DIR)/AnalysisAI

# Default target
all: $(BUILD_DIR) $(TARGET)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Link executable
$(TARGET): $(OBJECTS)
	@echo "Linking $@..."
	@$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "✓ Build complete: $@"

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(TARGET)
	@echo "✓ Clean complete"

# Clean and rebuild
rebuild: clean all

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing required packages..."
	@sudo apt-get update
	@sudo apt-get install -y build-essential uuid-dev libcurl4-openssl-dev libcjson-dev ltrace
	@echo "✓ Dependencies installed"

# Help target
help:
	@echo "AnalysisAI - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build the project (default)"
	@echo "  clean         - Remove build artifacts"
	@echo "  rebuild       - Clean and build"
	@echo "  install-deps  - Install required dependencies (requires sudo)"
	@echo "  help          - Display this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - gcc compiler"
	@echo "  - libuuid development files"
	@echo "  - libcurl development files"
	@echo "  - libcjson development files"
	@echo "  - ltrace utility"

.PHONY: all clean rebuild install-deps help
