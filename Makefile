BPF_CLANG ?= clang
CC ?= gcc

BPF_CFLAGS ?= -O2 -g -target bpf -Wall -I./bpf
USER_CFLAGS ?= -O2 -g -Wall -Wextra -I./bpf
USER_LDLIBS ?= -lbpf -lelf -lz

.PHONY: all clean run-loader run-ml

all: build/monitor.bpf.o build/loader

build:
	mkdir -p build

build/monitor.bpf.o: bpf/monitor.bpf.c bpf/vmlinux.h | build
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

build/loader: user/loader.c | build
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

run-loader: all
	sudo ./build/loader

run-ml:
	sudo -E python3 ml_engine.py

clean:
	rm -rf build
