# Compiler and flags
CC = clang
CFLAGS = -O2 -g
BPF_TARGET = -target bpf
INCLUDE_DIRS = -I./include -I./include/vmlinux -I/usr/include/$(uname -m)-linux-gnu

# File paths
SRC_DIR = ./scheds
BUILD_DIR = ./build
OBJ_DIR = $(BUILD_DIR)/obj
OUT_DIR = $(BUILD_DIR)/out

# Find all the source files that match the pattern
SRC_FILES = $(wildcard $(SRC_DIR)/scx_*.c)
BPF_SRC_FILES = $(wildcard $(SRC_DIR)/scx_*.bpf.c)

# Generate object and output file names based on the source files
BPF_OBJ_FILES = $(BPF_SRC_FILES:$(SRC_DIR)/%.bpf.c=$(OBJ_DIR)/%.bpf.o)
BPF_SKEL_FILES = $(BPF_OBJ_FILES:$(OBJ_DIR)/%.bpf.o=$(BUILD_DIR)/%.bpf.skel.h)
SRC_FILES_NO_BPF = $(filter-out $(SRC_DIR)/%.bpf.c, $(SRC_FILES))
NAMES = $(SRC_FILES_NO_BPF:$(SRC_DIR)/scx_%.c=%)
# Now generate OUT_FILES from the filtered list
OUT_FILES = $(SRC_FILES_NO_BPF:$(SRC_DIR)/%.c=$(OUT_DIR)/%.out)

$(foreach name, $(NAMES), $(eval $(name): $(OUT_DIR)/scx_$(name).out))

# Default target
all: $(OUT_FILES)

# Create necessary directories if they don't exist
$(OBJ_DIR) $(OUT_DIR):
	mkdir -p $@

# Rule to compile BPF object files
$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) $(BPF_TARGET) -c $< -o $@

# Rule to generate BPF skeleton headers
$(BUILD_DIR)/%.bpf.skel.h: $(OBJ_DIR)/%.bpf.o
	sudo ./bpftool gen skeleton $< name $* > $@

# Rule to compile the final executable
$(OUT_DIR)/%.out: $(SRC_DIR)/%.c $(BUILD_DIR)/%.bpf.skel.h $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -I./build -lbpf -g -o $@ $<

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all clean