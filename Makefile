CC = gcc
CLANG = clang
CFLAGS = -O2
BPF_CFLAGS = -O2 -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -g

all: pod-stats

pod-stats: src/main.c src/bpf_prog.o
	$(CC) $(CFLAGS) -o pod-stats src/main.c -lbpf

src/bpf_prog.o: src/bpf_prog.c src/pod_stats.h
	$(CLANG) $(BPF_CFLAGS) -c src/bpf_prog.c -o src/bpf_prog.o

clean:
	rm -f pod-stats src/bpf_prog.o

.PHONY: all clean
