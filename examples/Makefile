LLC ?= llc
CLANG ?= clang

test_pbf: test_bpf.o
	go build ./test_bpf.go

test_bpf.o: test_bpf.c
	$(CLANG) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
