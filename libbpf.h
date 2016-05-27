#ifndef __LIBBPF_H
#define __LIBBPF_H

/* bpf map structure used by C program to define maps and
 * used by elf loader.
 */
typedef struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
} bpf_map_def;

/* helper macro to place different sections in eBPF elf file. This is a generic
 * macro, more specific macro should be used instead of this one.
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper marcro to define a map, socket, kprobe section in the
 * eBPF elf file.
 */
#define MAP(NAME) __attribute__((section("maps/"NAME), used))
#define SOCKET(NAME) __attribute__((section("sockets/"NAME), used))
#define LICENSE SEC("license")

/* llvm built-in functions */
unsigned long long load_byte(void *skb,
  unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
  unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
  unsigned long long off) asm("llvm.bpf.load.word");

/* helper functions called from eBPF programs written in C
 */
static void *(*bpf_map_lookup_element)(void *map, void *key) =
  (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_element)(void *map, void *key, void *value,
  unsigned long long flags) = (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_element)(void *map, void *key) =
  (void *) BPF_FUNC_map_delete_elem;

#endif
