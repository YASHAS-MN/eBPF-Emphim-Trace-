CC ?= gcc
CLANG ?= clang-16
CFLAGS ?= -Wall -Wextra -O2
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86 -I src/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf")

BUILD_DIR = build
SRC_BPF = src/bpf/monitor.bpf.c
SRC_LOADER = src/user/loader.c

TEST_SRCS = $(wildcard tests/*.c)
TEST_BINS = $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))

all: $(BUILD_DIR)/monitor.bpf.o $(BUILD_DIR)/loader $(TEST_BINS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/monitor.bpf.o: $(SRC_BPF) src/bpf/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/loader: $(SRC_LOADER) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

$(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	$(CC) -O2 $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
