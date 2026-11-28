CC ?= gcc
CLANG ?= clang-16
CFLAGS ?= -Wall -Wextra -O2 -I src/user -I src/bpf
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86 -I src/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf")

BUILD_DIR = build
SRC_BPF = src/bpf/monitor.bpf.c
SRC_LOADER = src/user/loader.c
SRC_REPLAY = src/user/replay.c src/user/provenance.c

TEST_SRCS = $(wildcard tests1.0/*.c)
TEST_BINS = $(patsubst tests1.0/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))

all: $(BUILD_DIR)/monitor.bpf.o $(BUILD_DIR)/loader $(BUILD_DIR)/replay $(TEST_BINS)

loader: $(BUILD_DIR)/loader
replay: $(BUILD_DIR)/replay

test_m2_integration: $(BUILD_DIR)/test_m2_integration
test_m6_dag: $(BUILD_DIR)/test_m6_dag
test_m6_filtering: $(BUILD_DIR)/test_m6_filtering
test_m7_scenarios: $(BUILD_DIR)/test_m7_scenarios

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/monitor.bpf.o: $(SRC_BPF) src/bpf/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/loader: $(SRC_LOADER) src/user/evidence_io.h src/user/provenance.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(SRC_LOADER) -o $@ $(LIBBPF_LIBS)

$(BUILD_DIR)/replay: $(SRC_REPLAY) src/user/evidence_io.h src/user/provenance.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRC_REPLAY) -o $@

# Fault injection is linked only into the dedicated test replay binary.
$(BUILD_DIR)/replay_graph_fault: $(SRC_REPLAY) src/user/evidence_io.h src/user/provenance.h tests1.0/fault_injection/graph_alloc_wrap.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRC_REPLAY) tests1.0/fault_injection/graph_alloc_wrap.c -Wl,--wrap=calloc -o $@

$(BUILD_DIR)/test_graph_allocation_failure: tests1.0/test_graph_allocation_failure.c src/user/evidence_io.h src/user/provenance.h $(BUILD_DIR)/replay_graph_fault | $(BUILD_DIR)
	$(CC) -O2 -pthread -I src/user -I src/bpf $< -o $@

$(BUILD_DIR)/%: tests1.0/%.c | $(BUILD_DIR)
	$(CC) -O2 -pthread -I src/user -I src/bpf $< -o $@

clean:
	rm -rf $(BUILD_DIR)/* 2>/dev/null || true

.PHONY: all clean loader replay test_m2_integration test_m6_dag test_m6_filtering test_m7_scenarios
