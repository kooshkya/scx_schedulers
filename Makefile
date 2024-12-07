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
BPF_OBJ = $(OBJ_DIR)/scx_simple.bpf.o
BPF_SKEL = $(BUILD_DIR)/scx_simple.bpf.skel.h
OUT = $(OUT_DIR)/scx_simple.out
SRC = $(SRC_DIR)/scx_simple.c
BPF_SRC = $(SRC_DIR)/scx_simple.bpf.c

# Default target
all: $(OUT)

# Create necessary directories if they don't exist
$(OBJ_DIR) $(OUT_DIR):
	mkdir -p $@

# Rule to compile BPF object file
$(BPF_OBJ): $(BPF_SRC) $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) $(BPF_TARGET) -c $< -o $@

# Rule to generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	sudo ./bpftool gen skeleton $< name scx_simple > $@

# Rule to compile final executable
$(OUT): $(SRC) $(BPF_SKEL) $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -I./build -lbpf -g -o $@ $<

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all clean
