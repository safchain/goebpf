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

	fd, err := b.Attach("eth0")
	if err != nil {
		panic(err)
	}

	for i := 0; i != 50; i++ {
		value := make([]byte, 300)

		b.Map("my_map2").Lookup([]byte("abc"), value)
		fmt.Printf("Second map value: %v\n", value)

		time.Sleep(1 * time.Second)
	}

	err = b.Detach(fd)
	if err != nil {
		panic(err)
	}
}
