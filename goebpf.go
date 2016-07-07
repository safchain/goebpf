/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

// Package goebpf provides a simple library for handling eBPF programs. The eBPF
// programs have to be compiled with the header file coming with the package.
// This package provides a way to load the generated elf binaries and to do
// lookups on the eBPF maps.
package goebpf

/*
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "libbpf.h"

typedef struct bpf_map {
	int         fd;
	bpf_map_def def;
} bpf_map;

static __u64 ptr_to_u64(void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static void bpf_apply_relocation(int fd, struct bpf_insn *insn)
{
	insn->src_reg = BPF_PSEUDO_MAP_FD;
	insn->imm = fd;
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size,
	int value_size, int max_entries)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static bpf_map *bpf_load_map(bpf_map_def *map_def, int max)
{
	bpf_map *map;

	map = calloc(1, sizeof(bpf_map));
	if (map == NULL)
		return NULL;

	memcpy(&map->def, map_def, sizeof(bpf_map_def));

	if (max == 0)
		max = map_def->max_entries;

	map->fd = bpf_create_map(map_def->type,
		map_def->key_size,
		map_def->value_size,
		max
	);

	if (map->fd < 0)
		return 0;

	return map;
}

static int bpf_attach(int prog_fd, int fd)
{
	return setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &(prog_fd),
		sizeof(prog_fd)) == 0;
}

static int bpf_detach(int prog_fd, int fd)
{
	return setsockopt(fd, SOL_SOCKET, SO_DETACH_BPF, &(prog_fd),
		sizeof(prog_fd)) == 0;
}

static int bpf_prog_load(enum bpf_prog_type prog_type,
	const struct bpf_insn *insns, int prog_len,
	const char *license, int kern_version,
	char *log_buf, int log_size)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.prog_type = prog_type;
	attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
	attr.insns = ptr_to_u64((void *) insns);
	attr.license = ptr_to_u64((void *) license);
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_size;
	attr.log_level = 1;
	attr.kern_version = kern_version;

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_delete_element(int fd, void *key)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key)
	};

	return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) == 0;
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.next_key = ptr_to_u64(next_key),
	};

	return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0;
}

int bpf_lookup_element(int fd, void *key, void *value)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(value),
	};

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0;
}

int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int fd;

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
		htons(ETH_P_ALL));
	if (fd < 0)
		return 0;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		close(fd);
		return 0;
	}

	return fd;
}
*/
import "C"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// A BPFMapType represents a eBPF map type
type BPFMapType uint32

// Types of maps
const (
	BPF_MAP_TYPE_UNSPEC BPFMapType = C.BPF_MAP_TYPE_UNSPEC
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
)

// BPFMap represents a eBPF map. An eBPF map has to be declared in the C file
// using the macro MAP provided by the libbpf.h header file.
type BPFMap struct {
	Name string
	m    *C.bpf_map
}

type BPFMapIterator struct {
	key interface{}
	m   *BPFMap
}

// BPFMap represents a eBPF program.
type BPFProg struct {
	file                  *elf.File
	fd                    int
	prog_map              *BPFMap
	maps                  map[string]*BPFMap
	log                   []byte
	verifierLogLevel      int
	mapsDefaultMaxEntries int
	mapsMaxEntries        map[string]int
}

// Release releases the memory allocated by a BPFProg.
func (b *BPFProg) Release() {
	for _, m := range b.maps {
		C.free(unsafe.Pointer(m.m))
	}
}

// Log returns the log output coming from the eBPF program.
func (b *BPFProg) Log() []byte {
	return b.log
}

// Type returns the type of a BPFMap wich is the type of the eBPF map.
func (m *BPFMap) Type() BPFMapType {
	return BPFMapType(m.m.def._type)
}

// KeySize returns the key size of a BPFMap/eBPF map.
func (m *BPFMap) KeySize() uint32 {
	return uint32(m.m.def.key_size)
}

// ValueSize returns the value size of a BPFMap/eBPF map.
func (m *BPFMap) ValueSize() uint32 {
	return uint32(m.m.def.value_size)
}

// Lookup does a lookup on the corresponding BPFMap. Key/values parameters
// need to be pointers and need to be be used according to the eBPF map
// definition declared in the eBPF C file. See the libbpf.h file coming with
// this package.
func (m *BPFMap) Lookup(key interface{}, value interface{}) bool {
	if m == nil {
		return false
	}

	k := reflect.ValueOf(key)
	v := reflect.ValueOf(value)

	ret := C.bpf_lookup_element(m.m.fd, unsafe.Pointer(k.Pointer()), unsafe.Pointer(v.Pointer()))
	if ret == 0 {
		return false
	}

	return true
}

// Delete deletes the map entry for the given key.
func (m *BPFMap) Delete(key interface{}) bool {
	if m == nil {
		return false
	}

	k := reflect.ValueOf(key)

	ret := C.bpf_delete_element(m.m.fd, unsafe.Pointer(k.Pointer()))
	if ret == 0 {
		return false
	}

	return true
}

// Iterator returns a BPFMapIterator
func (m *BPFMap) Iterator() *BPFMapIterator {
	return &BPFMapIterator{
		key: make([]byte, m.KeySize()),
		m:   m,
	}
}

// Next returns the next key, value of the BPFMap, returns true when
// the next element has been found, false otherwise.
func (i *BPFMapIterator) Next(key interface{}, value interface{}) bool {
	k := reflect.ValueOf(i.key)
	nk := reflect.ValueOf(key)

	ret := C.bpf_get_next_key(i.m.m.fd, unsafe.Pointer(k.Pointer()), unsafe.Pointer(nk.Pointer()))
	if ret == 0 {
		return false
	}

	found := i.m.Lookup(key, value)
	if found {
		i.key = key
		return true
	}

	return false
}

// Attach attaches the eBPF program to the given interface.
func (b *BPFProg) Attach(ifname string) (int, error) {
	li := unsafe.Pointer(C.CString(ifname))
	defer C.free(li)

	fd := C.open_raw_sock((*C.char)(li))
	if fd == 0 {
		return 0, errors.New("Unable to open raw socket")
	}

	ret := C.bpf_attach(C.int(b.fd), fd)
	if ret == 0 {
		return 0, errors.New("Unable to attach bpf to raw socket")
	}

	return int(fd), nil
}

// Detach detaches the eBPF program to the given interface.
func (b *BPFProg) Detach(fd int) error {
	ret := C.bpf_attach(C.int(b.fd), C.int(fd))
	if ret == 0 {
		return errors.New("Unable to detach bpf to raw socket")
	}
	return nil
}

func (b *BPFProg) relocate(data []byte, rdata []byte) error {
	var symbol elf.Symbol
	var offset uint64

	symbols, err := b.file.Symbols()
	if err != nil {
		return err
	}

	br := bytes.NewReader(data)

	for {
		switch b.file.Class {
		case elf.ELFCLASS64:
			var rel elf.Rel64
			err := binary.Read(br, b.file.ByteOrder, &rel)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}

			symNo := rel.Info >> 32
			symbol = symbols[symNo-1]

			offset = rel.Off
		case elf.ELFCLASS32:
			var rel elf.Rel32
			err := binary.Read(br, b.file.ByteOrder, &rel)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}

			symNo := rel.Info >> 8
			symbol = symbols[symNo-1]

			offset = uint64(rel.Off)
		default:
			return errors.New("Architecture not supported")
		}

		rinsn := (*C.struct_bpf_insn)(unsafe.Pointer(&rdata[offset]))
		if rinsn.code != (C.BPF_LD | C.BPF_IMM | C.BPF_DW) {
			return errors.New("Invalid relocation")
		}

		symbolSec := b.file.Sections[symbol.Section]
		name := strings.TrimPrefix(symbolSec.Name, "maps/")

		m := b.Map(name)
		if m == nil {
			return errors.New("Relocation error, map not found")
		}

		C.bpf_apply_relocation(m.m.fd, rinsn)
	}
}

func (b *BPFProg) readLicense() (string, error) {
	if lsec := b.file.Section("license"); lsec != nil {
		data, err := lsec.Data()
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	return "", nil
}

func (b *BPFProg) readVersion() (int64, error) {
	if vsec := b.file.Section("version"); vsec != nil {
		data, err := vsec.Data()
		if err != nil {
			return 0, err
		}
		version, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return 0, err
		}
		return version, nil
	}

	return 0, nil
}

func (b *BPFProg) readMaps() error {
	for _, section := range b.file.Sections {
		if strings.HasPrefix(section.Name, "maps/") {
			data, err := section.Data()
			if err != nil {
				return err
			}

			name := strings.TrimPrefix(section.Name, "maps/")

			maxEntries := b.mapsMaxEntries[name]
			if maxEntries == 0 {
				maxEntries = b.mapsDefaultMaxEntries
			}

			cm := C.bpf_load_map((*C.bpf_map_def)(unsafe.Pointer(&data[0])), C.int(maxEntries))
			if cm == nil {
				return fmt.Errorf("Error while loading map %s", section.Name)
			}

			m := &BPFMap{Name: name, m: cm}

			if m.Type() == BPF_MAP_TYPE_PROG_ARRAY {
				b.prog_map = m
			}

			b.maps[name] = m
		}
	}

	return nil
}

func (b *BPFProg) load() error {
	license, err := b.readLicense()
	if err != nil {
		return err
	}

	lp := unsafe.Pointer(C.CString(license))
	defer C.free(lp)

	version, err := b.readVersion()
	if err != nil {
		return err
	}

	err = b.readMaps()
	if err != nil {
		return err
	}

	processed := make([]bool, len(b.file.Sections))
	for i, section := range b.file.Sections {
		if processed[i] {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return err
		}

		if len(data) == 0 {
			continue
		}

		if section.Type == elf.SHT_REL {
			rsection := b.file.Sections[section.Info]

			processed[i] = true
			processed[section.Info] = true

			if strings.HasPrefix(rsection.Name, "sockets/") {
				rdata, err := rsection.Data()
				if err != nil {
					return err
				}

				if len(rdata) == 0 {
					continue
				}

				err = b.relocate(data, rdata)
				if err != nil {
					return err
				}

				insns := (*C.struct_bpf_insn)(unsafe.Pointer(&rdata[0]))

				fd := C.bpf_prog_load(C.BPF_PROG_TYPE_SOCKET_FILTER,
					insns, C.int(rsection.Size),
					(*C.char)(lp), C.int(version),
					(*C.char)(unsafe.Pointer(&b.log[0])), C.int(len(b.log)))
				if fd < 0 {
					return errors.New("Error while loading")
				}
				b.fd = int(fd)
			}
		}
	}

	for i, section := range b.file.Sections {
		if processed[i] {
			continue
		}

		if strings.HasPrefix(section.Name, "sockets/") {
			data, err := section.Data()
			if err != nil {
				panic(err)
			}

			if len(data) == 0 {
				continue
			}

			insns := (*C.struct_bpf_insn)(unsafe.Pointer(&data[0]))

			fd := C.bpf_prog_load(C.BPF_PROG_TYPE_SOCKET_FILTER,
				insns, C.int(section.Size),
				(*C.char)(lp), C.int(version),
				(*C.char)(unsafe.Pointer(&b.log[0])), C.int(len(b.log)))
			if fd < 0 {
				panic(errors.New("Error while loading bpf prog"))
			}
			b.fd = int(fd)
		}
	}

	return nil
}

// Map returns the BPFMap for the given name. The name is the name used for
// the map declaration with the MAP macro is the eBPF C file.
func (b *BPFProg) Map(name string) *BPFMap {
	return b.maps[name]
}

// Maps returns a map of BPFMap indexed by their name
func (b *BPFProg) Maps() map[string]*BPFMap {
	return b.maps
}

// Load loads the elf eBPF binary
func (b *BPFProg) Load() error {
	if err := b.load(); err != nil {
		return err
	}
	return nil
}

// SetDefaultMaxEntries sets the default max_entries for all the maps
// that will be loaded, if not defined the value
func (b *BPFProg) SetDefaultMaxEntries(max int) {
	b.mapsDefaultMaxEntries = max
}

func (b *BPFProg) SetMaxEntries(table string, max int) {
	b.mapsMaxEntries[table] = max
}

// NewBPFProg returns a new BPFProg
func NewBPFProg(r io.ReaderAt) (*BPFProg, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	b := &BPFProg{
		file:           f,
		maps:           make(map[string]*BPFMap),
		log:            make([]byte, 65536),
		mapsMaxEntries: make(map[string]int),
	}

	return b, nil
}
