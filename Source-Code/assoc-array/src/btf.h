#ifndef K2_BTF_H
#define K2_BTF_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Minimal read-only BTF reader for /sys/kernel/btf/vmlinux.  It only has to
 * answer "what is the byte offset of member X of struct Y" for types the
 * distro toolchain kept in the image, which removes the per-build offset
 * pinning of the original harness.
 */

typedef int btf_id_t;

int btf_open(void);
void btf_close(void);
bool btf_is_open(void);

/* -ENOENT when the type is absent from this image. */
int btf_find_struct(const char *name);
int btf_struct_size(btf_id_t type, uint32_t *size_out);
/* -ENOENT when the member does not exist; *byte_off_out is set otherwise. */
int btf_member_offset(btf_id_t type, const char *member,
                      uint32_t *byte_off_out);
int btf_member_type(btf_id_t type, const char *member, btf_id_t *type_out);
int btf_member_size(btf_id_t type, const char *member, uint32_t *size_out);
int btf_enum_value(const char *enum_name, const char *member,
                   uint32_t *value_out);
uint32_t btf_scalar_size(btf_id_t type);

#endif
