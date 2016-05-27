package main

import (
	"fmt"
	"os"
	"time"

	"github.com/safchain/goebpf"
)

func main() {
	f, err := os.Open("test_bpf.o")
	if err != nil {
		panic(err)
	}

	b, err := goebpf.NewBPFProg(f)
	if err != nil {
		if b != nil {
			fmt.Println(string(b.Log()))
		}
		panic(err)
	}
	defer b.Release()

	fmt.Println(string(b.Log()))

	fd, err := b.Attach("lo")
	if err != nil {
		panic(err)
	}

	for i := 0; i != 5; i++ {
		key := uint32(1)
		var value uint64

		b.Map("first").Lookup(&key, &value)
		fmt.Printf("First map value: %d\n", value)

		b.Map("second").Lookup([]byte("abc"), &value)
		fmt.Printf("Second map value: %d\n", value)

		time.Sleep(1 * time.Second)
	}

	err = b.Detach(fd)
	if err != nil {
		panic(err)
	}
}
