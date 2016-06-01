LLC ?= llc
CLANG ?= clang

all: test_bpf test_ft

test_pbf: ../goebpf.go test_bpf.go test_bpf.o
	go build ./test_bpf.go

test_ft: ../goebpf.go test_ft.go test_ft.o
	go build ./test_ft.go

%.o: %.c
	$(CLANG) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
