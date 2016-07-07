package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/safchain/goebpf"
)

// #include "test_ft.h"
import "C"

func uint32ToIPV4(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}

func main() {
	f, err := os.Open("test_ft.o")
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

	_, err = b.Attach("wlp4s0")
	if err != nil {
		panic(err)
	}

	var start int64
	flow := C.struct_flow{}

	for {
		var info syscall.Sysinfo_t
		syscall.Sysinfo(&info)

		count := 0

		it := b.Map("flow_table").Iterator()
		for it.Next(&flow.key, &flow) {
			linkSrc := C.GoBytes(unsafe.Pointer(&flow.key.link_layer.mac_src[0]), C.ETH_ALEN)
			linkDst := C.GoBytes(unsafe.Pointer(&flow.key.link_layer.mac_dst[0]), C.ETH_ALEN)

			macSrc := net.HardwareAddr(linkSrc).String()
			macDst := net.HardwareAddr(linkDst).String()

			packets := uint64(flow.stats.link_layer.packets)
			bytes := uint64(flow.stats.link_layer.bytes)

			fmt.Printf("%s ==> %s : %d packets, %d bytes\n", macSrc, macDst, packets, bytes)

			ipSrc := uint32(flow.key.network_layer.ip_src)
			ipDst := uint32(flow.key.network_layer.ip_dst)

			packets = uint64(flow.stats.network_layer.packets)
			bytes = uint64(flow.stats.network_layer.bytes)

			fmt.Printf("\t%s ==> %s : %d packets, %d bytes\n",
				uint32ToIPV4(ipSrc).String(), uint32ToIPV4(ipDst).String(), packets, bytes)

			protocol := uint8(flow.key.transport_layer.protocol)
			portSrc := uint32(flow.key.transport_layer.port_src)
			portDst := uint32(flow.key.transport_layer.port_dst)

			packets = uint64(flow.stats.transport_layer.packets)
			bytes = uint64(flow.stats.transport_layer.bytes)

			fmt.Printf("\t%d: %d ==> %d : %d packets, %d bytes\n",
				protocol, portSrc, portDst, packets, bytes)

			if start == 0 {
				start = int64(flow.start)
			}

			last := int64(flow.last)
			if last-start > int64(10*time.Second) {
				b.Map("flow_table").Delete(&flow.key)
			}

			count++
		}
		fmt.Printf("-------------------- Total: %d -------------------\n", count)
		time.Sleep(1 * time.Second)
	}
}
