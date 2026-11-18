# assoc_array shortcut-chain (K2 port)

Kernel LPE: `lib/assoc_array.c`, reachable through the keyrings syscalls.
Unprivileged local user to `CAP_DAC_OVERRIDE`/`CAP_SETUID` and then to a root
shell. No namespaces, no capabilities, no FUSE, no user interaction.

|              |                                                                 |
|--------------|-----------------------------------------------------------------|
| CVE          | none assigned                                                   |
| Root cause   | `assoc_array_insert_into_terminal_node()` replaces a full node with a shortcut; if that node was already a shortcut's target, the new shortcut lands behind the old one |
| Introduced   | `3cb989501c26` (2013), so every 3.9+ kernel                    |
| Fixed by     | `48691075b0ad` (Linus Torvalds, reported by Nils Ollrogge) — public, not in mainline as of 2026-11-15 |
| Trigger      | 18 insertions and a deletion, then one more `add_key(2)`        |
| Privileges   | local unprivileged user, no capabilities, no namespaces          |
| Requires     | x86_64, 4K pages, `CONFIG_KEYS`, unprivileged `AF_ALG` (`xts(aes)`), readable `/proc` |
| Success check | `CapEff` gains the low 32 bits, `/flag` / `/etc/shadow` becomes readable, then `setresuid(0,0,0)` + shell |

Original chain and harness: [Rat5ak/ASSOC_ARRAY_SHORTCUT-CHAIN-EoP](https://github.com/Rat5ak/ASSOC_ARRAY_SHORTCUT-CHAIN-EoP)
(kernelCTF hardened 7.2-rc5, one pinned image). This copy is portable: the
KASLR fingerprints, the 936 KB rodata target table and every struct offset are
resolved on the target instead of being compiled in.

## What it does

1. `add_key()` builds 16 `user` keys whose index hashes collide, plus an
   outlier that is deleted again, plus one more key — the exact recipe from the
   fix commit.
2. The last `add_key` installs a shortcut behind a shortcut, which the tree
   treats as impossible. `assoc_array_apply_edit()` hits `BUG_ON()`; only the
   inserting thread dies.
3. A reader parked in `key_link` is already walking that broken tree and
   lands on an attacker-controlled allocation it believes is a `struct key`.
4. The fake key's `user` pointer sits eight bytes below a real `struct cred`,
   so the kernel's own key-quota bookkeeping writes into `cap_effective`.
5. `setresuid(0,0,0)` + `execve` — the kernel then grants the full set
   legitimately, because euid is 0.

## Portability

Everything the original pinned is discovered here:

* `key_type_user` / `default_domain_tag` from `/proc/kallsyms`,
  `/boot/System.map-*` or a leaked `struct key` slab page, verified with an
  assoc-array order probe before anything else runs;
* all struct offsets from BTF (`/sys/kernel/btf/vmlinux`), including the
  `assoc_array_node.slots` offset and the `KEY_FLAG_*` values, with `K2_OFF_*`
  overrides for BTF-less kernels;
* the target description, its 16 hash collisions and the outlier are generated
  at runtime; the description is hosted inside the fake payload;
* the SLUB freepointer offset is probed, the `filp` geometry is derived from
  `sizeof(struct file)`, the slab window comes from the first captured page;
* the rank-census width adapts to `kernel.keys.maxkeys` / `maxbytes`.

## Build

```
cd Source-Code/assoc-array
make                  # -> ./exploit
make install          # -> ../../xpl2026/assoc-array-static
```

`make` needs gcc, a static glibc and `objcopy`.

## Run

```
./assoc-array-static                 # full chain
./assoc-array-static --layout        # probed layout only
./assoc-array-static --leak-only     # leak + verify key_type_user
./assoc-array-static --selftest      # offline self test
./assoc-array-static --vuln-trigger  # deterministic BUG only
```

## Caveats

* **`panic_on_oops=1`** (Debian/Ubuntu default): the `BUG()` panics. The second
  CPU only has the oops-printing window to apply the quota write and read the
  proof file, and the shell is only exec'd when `panic_on_oops=0`. A reboot
  restores everything — this exploit is not persistent by construction.
* **Key quota.** The original geometry wants ~800 live keys; stock quotas are
  `maxkeys=200`, `maxbytes=20000`, so the profile is squeezed (`FULL_CHAIN_PROFILE`
  prints it). Raising both sysctls beforehand gives the roomier, tested shape.
* The rank-census constants (352 prefix / 288 critical out of 640) were tuned
  on 2 vCPU. Other CPU counts change the statistics.
* Needs `KEYCTL_RESTRICT_KEYRING` (>= 4.13) and `MEMBARRIER_CMD_GLOBAL` (>= 4.14).
* Not supported: 64K pages (arm64), non-x86_64, kernels with `48691075b0ad`.

## Expected output (trimmed)

```
[*] assoc_array shortcut-chain: K2 port. uid=1000 panic_on_oops=0 ...
GATE_ENVIRONMENT ok cpus=2 page=4096 uid=1000 machine=x86_64
K2_LAYOUT ... key.user=0x40 ... cred.cap_effective=0x40 ...
[+] key_type_user=0xffffffff... default_domain_tag=0xffffffff... (source=kallsyms)
K2_FREEPTR_PROBE offset=128 base=0xffff...
INTEGRATED_FATAL_ADD cpu=0 source=...; syscall should not return
kernel BUG at lib/assoc_array.c:1387!
[+] GADGET_CAP_WRITE_OBSERVED proof_rc=0
[+] GADGET_ROOT uid=0 euid=0 CapEff=00000000ffffffff panic_on_oops=0
```

Credit: bug by **Nils Ollrogge**, fix by **Linus Torvalds**, reviewed by
**David Howells**; original exploit chain by **Daniel Wade (Rat5ak)**.
