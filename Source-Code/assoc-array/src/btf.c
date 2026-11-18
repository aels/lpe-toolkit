#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "btf.h"

/*
 * Read-only BTF reader.  Only forwards declarations are relevant and only a
 * handful of queries are made, so every lookup simply walks the type section.
 * Nothing here is on the timing critical path of the exploit.
 */

#define BTF_MAGIC 0xeb9fU
#define BTF_KIND_MASK 0x1fU
#define BTF_KFLAG_SHIFT 31
#define BTF_VLEN_MASK 0xffffU

enum {
    BTF_KIND_UNKN = 0,
    BTF_KIND_INT = 1,
    BTF_KIND_PTR = 2,
    BTF_KIND_ARRAY = 3,
    BTF_KIND_STRUCT = 4,
    BTF_KIND_UNION = 5,
    BTF_KIND_ENUM = 6,
    BTF_KIND_FWD = 7,
    BTF_KIND_TYPEDEF = 8,
    BTF_KIND_VOLATILE = 9,
    BTF_KIND_CONST = 10,
    BTF_KIND_RESTRICT = 11,
    BTF_KIND_FUNC = 12,
    BTF_KIND_FUNC_PROTO = 13,
    BTF_KIND_VAR = 14,
    BTF_KIND_DATASEC = 15,
    BTF_KIND_FLOAT = 16,
    BTF_KIND_DECL_TAG = 17,
    BTF_KIND_TYPE_TAG = 18,
    BTF_KIND_ENUM64 = 19,
};

struct btf_header {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
};

struct btf_type {
    uint32_t name_off;
    uint32_t info;
    uint32_t size_or_type;
};

struct btf_member {
    uint32_t name_off;
    uint32_t type;
    uint32_t offset;
};

static struct {
    unsigned char *map;
    size_t map_len;
    const unsigned char *types;
    size_t types_len;
    const char *strings;
    size_t strings_len;
    bool open;
} btf;

static int btf_type_payload(uint32_t kind, uint32_t vlen, size_t *payload)
{
    switch (kind) {
    case BTF_KIND_INT:
    case BTF_KIND_VAR:
    case BTF_KIND_DECL_TAG:
        *payload = 4;
        return 0;
    case BTF_KIND_ARRAY:
        *payload = 12;
        return 0;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
    case BTF_KIND_DATASEC:
    case BTF_KIND_ENUM64:
        *payload = (size_t)vlen * 12;
        return 0;
    case BTF_KIND_ENUM:
    case BTF_KIND_FUNC_PROTO:
        *payload = (size_t)vlen * 8;
        return 0;
    case BTF_KIND_PTR:
    case BTF_KIND_FWD:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_FUNC:
    case BTF_KIND_FLOAT:
    case BTF_KIND_TYPE_TAG:
        *payload = 0;
        return 0;
    default:
        return -ENOTSUP;
    }
}

static int btf_advance(size_t offset, struct btf_type *out, size_t *next)
{
    uint32_t kind, vlen;
    size_t payload;

    if (offset + sizeof(*out) > btf.types_len)
        return -EINVAL;
    memcpy(out, btf.types + offset, sizeof(*out));
    kind = (out->info >> 24) & BTF_KIND_MASK;
    vlen = out->info & BTF_VLEN_MASK;
    if (btf_type_payload(kind, vlen, &payload) != 0)
        return -ENOTSUP;
    if (offset + sizeof(*out) + payload > btf.types_len)
        return -EINVAL;
    *next = offset + sizeof(*out) + payload;
    return 0;
}

static const char *btf_string(uint32_t offset)
{
    if (offset >= btf.strings_len)
        return NULL;
    return btf.strings + offset;
}

static bool btf_name_is(uint32_t name_off, const char *name)
{
    const char *candidate = btf_string(name_off);

    return candidate && strcmp(candidate, name) == 0;
}

int btf_open(void)
{
    const char *path = "/sys/kernel/btf/vmlinux";
    struct btf_header header;
    struct stat info;
    int fd;

    if (btf.open)
        return 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    if (fstat(fd, &info) < 0) {
        int rc = -errno;

        close(fd);
        return rc;
    }
    if (!S_ISREG(info.st_mode) || info.st_size < (off_t)sizeof(header)) {
        close(fd);
        return -ENODATA;
    }
    btf.map = mmap(NULL, (size_t)info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (btf.map == MAP_FAILED) {
        btf.map = NULL;
        return -errno;
    }
    btf.map_len = (size_t)info.st_size;
    memcpy(&header, btf.map, sizeof(header));
    if (header.magic != BTF_MAGIC) {
        btf_close();
        return -ENODATA;
    }
    if (header.hdr_len < sizeof(header) ||
        (size_t)header.hdr_len + header.type_off + header.type_len >
            btf.map_len ||
        (size_t)header.hdr_len + header.str_off + header.str_len >
            btf.map_len) {
        btf_close();
        return -EINVAL;
    }
    btf.types = btf.map + header.hdr_len + header.type_off;
    btf.types_len = header.type_len;
    btf.strings = (const char *)btf.map + header.hdr_len + header.str_off;
    btf.strings_len = header.str_len;
    btf.open = true;
    return 0;
}

void btf_close(void)
{
    if (btf.map)
        munmap(btf.map, btf.map_len);
    memset(&btf, 0, sizeof(btf));
}

bool btf_is_open(void)
{
    return btf.open;
}

/* Type ids start at 1; id 0 is void. */
int btf_find_struct(const char *name)
{
    size_t offset = 0;
    int id = 1;

    if (!btf.open)
        return -ENODATA;
    while (offset < btf.types_len) {
        struct btf_type type;
        uint32_t kind;
        size_t next;
        int rc = btf_advance(offset, &type, &next);

        if (rc)
            return rc;
        kind = (type.info >> 24) & BTF_KIND_MASK;
        if ((kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) &&
            btf_name_is(type.name_off, name))
            return id;
        offset = next;
        id++;
    }
    return -ENOENT;
}

static int btf_lookup(btf_id_t wanted, struct btf_type *out, size_t *body)
{
    size_t offset = 0;
    int id = 1;

    if (!btf.open)
        return -ENODATA;
    if (wanted <= 0)
        return -EINVAL;
    while (offset < btf.types_len) {
        size_t next;
        int rc = btf_advance(offset, out, &next);

        if (rc)
            return rc;
        if (id == wanted) {
            *body = offset + sizeof(*out);
            return 0;
        }
        offset = next;
        id++;
    }
    return -ENOENT;
}

int btf_struct_size(btf_id_t type, uint32_t *size_out)
{
    struct btf_type record;
    size_t body;
    int rc = btf_lookup(type, &record, &body);

    if (rc)
        return rc;
    *size_out = record.size_or_type;
    return 0;
}

static int btf_find_member(btf_id_t type, const char *member,
                           struct btf_member *out)
{
    struct btf_type record;
    size_t body;
    uint32_t vlen;
    int rc = btf_lookup(type, &record, &body);

    if (rc)
        return rc;
    vlen = record.info & BTF_VLEN_MASK;
    for (uint32_t i = 0; i < vlen; i++) {
        struct btf_member entry;

        memcpy(&entry, btf.types + body + i * sizeof(entry), sizeof(entry));
        if (btf_name_is(entry.name_off, member)) {
            *out = entry;
            return 0;
        }
    }
    return -ENOENT;
}

int btf_member_offset(btf_id_t type, const char *member,
                      uint32_t *byte_off_out)
{
    struct btf_member entry;
    struct btf_type record;
    size_t body;
    uint32_t kind, bits;
    int rc;

    rc = btf_lookup(type, &record, &body);
    if (rc)
        return rc;
    kind = (record.info >> 24) & BTF_KIND_MASK;
    if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION)
        return -EINVAL;
    rc = btf_find_member(type, member, &entry);
    if (rc)
        return rc;
    bits = entry.offset;
    if (record.info >> BTF_KFLAG_SHIFT)
        bits &= 0xffffffU;
    if (bits % 8)
        return -ENOTSUP;
    *byte_off_out = bits / 8;
    return 0;
}

int btf_member_type(btf_id_t type, const char *member, btf_id_t *type_out)
{
    struct btf_member entry;
    int rc = btf_find_member(type, member, &entry);

    if (rc)
        return rc;
    *type_out = (btf_id_t)entry.type;
    return 0;
}

static int btf_type_size(btf_id_t type, uint32_t *size_out)
{
    struct btf_type record;
    size_t body;
    uint32_t kind;
    int rc;

    for (unsigned int depth = 0; depth < 8; depth++) {
        rc = btf_lookup(type, &record, &body);
        if (rc)
            return rc;
        kind = (record.info >> 24) & BTF_KIND_MASK;
        switch (kind) {
        case BTF_KIND_INT:
        case BTF_KIND_FLOAT:
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
        case BTF_KIND_ENUM:
        case BTF_KIND_ENUM64:
        case BTF_KIND_DATASEC:
            *size_out = record.size_or_type;
            return 0;
        case BTF_KIND_PTR:
            *size_out = sizeof(void *);
            return 0;
        case BTF_KIND_ARRAY: {
            uint32_t element, count, nested;

            memcpy(&element, btf.types + body, sizeof(element));
            memcpy(&count, btf.types + body + 8, sizeof(count));
            rc = btf_type_size((btf_id_t)element, &nested);
            if (rc)
                return rc;
            *size_out = nested * count;
            return 0;
        }
        case BTF_KIND_TYPEDEF:
        case BTF_KIND_VOLATILE:
        case BTF_KIND_CONST:
        case BTF_KIND_RESTRICT:
        case BTF_KIND_TYPE_TAG:
            type = (btf_id_t)record.size_or_type;
            continue;
        default:
            return -ENOTSUP;
        }
    }
    return -ELOOP;
}

int btf_member_size(btf_id_t type, const char *member, uint32_t *size_out)
{
    struct btf_member entry;
    int rc = btf_find_member(type, member, &entry);

    if (rc)
        return rc;
    return btf_type_size((btf_id_t)entry.type, size_out);
}

uint32_t btf_scalar_size(btf_id_t type)
{
    uint32_t size = 0;

    if (btf_type_size(type, &size) != 0)
        return 0;
    return size;
}

int btf_enum_value(const char *enum_name, const char *member,
                   uint32_t *value_out)
{
    size_t offset = 0;

    if (!btf.open)
        return -ENODATA;
    while (offset < btf.types_len) {
        struct btf_type type;
        uint32_t kind, vlen;
        size_t next, body;
        int rc = btf_advance(offset, &type, &next);

        if (rc)
            return rc;
        kind = (type.info >> 24) & BTF_KIND_MASK;
        if ((kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) &&
            btf_name_is(type.name_off, enum_name)) {
            vlen = type.info & BTF_VLEN_MASK;
            body = offset + sizeof(type);
            for (uint32_t i = 0; i < vlen; i++) {
                size_t entry = kind == BTF_KIND_ENUM ? i * 8 : i * 12;
                uint32_t name_off, value = 0;

                memcpy(&name_off, btf.types + body + entry, sizeof(name_off));
                memcpy(&value, btf.types + body + entry + 4, sizeof(value));
                if (btf_name_is(name_off, member)) {
                    *value_out = value;
                    return 0;
                }
            }
            return -ENOENT;
        }
        offset = next;
    }
    return -ENOENT;
}
