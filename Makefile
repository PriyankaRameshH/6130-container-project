CC ?= gcc
CLANG ?= clang
STRIP ?= llvm-strip

BPF_C := internal/bpf/escape_detector.bpf.c
BPF_OBJ := internal/bpf/escape_detector.bpf.o
APP_C := cmd/detector/detector.c
BIN := bin/detector

BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -I/usr/include/$(shell uname -m)-linux-gnu
APP_CFLAGS := -O2 -g -Wall -Wextra
APP_LDFLAGS := -lbpf -lelf -lz

.PHONY: all bpf build run clean

all: bpf build

bpf:
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_C) -o $(BPF_OBJ)
	$(STRIP) -g $(BPF_OBJ)

build:
	mkdir -p bin
	$(CC) $(APP_CFLAGS) $(APP_C) -o $(BIN) $(APP_LDFLAGS)

run: all
	sudo ./$(BIN) -policy examples/policy.yaml

clean:
	rm -rf bin
	rm -f $(BPF_OBJ)
