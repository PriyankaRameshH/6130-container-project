CC ?= gcc
CLANG ?= clang
STRIP ?= llvm-strip

BPF_C := internal/bpf/escape_detector.bpf.c
BPF_OBJ := internal/bpf/escape_detector.bpf.o
APP_C := cmd/detector/detector.c
BIN := bin/detector
SIM_C := scripts/simulate_attack.c
SIM_BIN := bin/simulate_attack

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
	$(CC) $(APP_CFLAGS) $(SIM_C) -o $(SIM_BIN)

run: all
	sudo ./$(BIN) -policy examples/policy.yaml

demo: all
	sudo bash scripts/run_demo.sh

demo-json: all
	sudo bash scripts/run_demo.sh --json

# Real container escape attack demos
real-attack: all
	sudo bash attacks/run_real_attacks.sh

real-attack-json: all
	sudo bash attacks/run_real_attacks.sh --json

real-attack1: all
	sudo bash attacks/run_real_attacks.sh --attack 1

real-attack2: all
	sudo bash attacks/run_real_attacks.sh --attack 2

real-attack3: all
	sudo bash attacks/run_real_attacks.sh --attack 3

clean:
	rm -rf bin
	rm -f $(BPF_OBJ)
