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
		panic(err)
	}
	defer b.Release()

	b.SetDefaultMaxEntries(300)

	err = b.Load()
	if err != nil {
		fmt.Println(string(b.Log()))
		panic(err)
	}

	fmt.Println(string(b.Log()))

	fmt.Println(b.Maps())

	fd, err := b.Attach("wlp4s0")
	if err != nil {
		panic(err)
	}

	for i := 0; i != 50; i++ {
		value := make([]byte, 300)

        key := uint32(44)

		b.Map("my_map1").Lookup(&key, value)
		fmt.Printf("First map value: %v\n", value)


		b.Map("my_map2").Lookup([]byte("abc"), value)
		fmt.Printf("Second map value: %v\n", value)

		time.Sleep(1 * time.Second)
	}

	err = b.Detach(fd)
	if err != nil {
		panic(err)
	}
}
