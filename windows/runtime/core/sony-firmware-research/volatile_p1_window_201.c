/* Offline-only A7C II 2.01 fixed-node p1 block-window reader.
 * Build once per exact, allowlisted node with literal -D constants. The
 * constructor accepts only the matching node, dev_t and capacity, reads one
 * <=8-MiB window, then exits. The next invocation removes exactly the prior
 * capture's tmpfs window before creating its successor. Source is O_RDONLY;
 * only helper-owned tmpfs files are created/deleted. Never point at SD media.
 */

#if !defined(TARGET_PARTITION_ID) || !defined(TARGET_EXPECTED_KIB) || \
    !defined(TARGET_MINOR) || !defined(TARGET_TOTAL_CHUNKS) || \
    !defined(TARGET_NAME) || !defined(TARGET_P_NAME) || \
    !defined(TARGET_C_NAME) || !defined(TARGET_TAG) || \
    !defined(TARGET_DEVICE_PATH) || !defined(TARGET_REQUEST_PATH) || \
    !defined(TARGET_OUTPUT_PREFIX) || !defined(TARGET_WHOLE)
#error "compile a fixed allowlisted owner block target"
#endif

typedef unsigned long usize;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;

static long sc4(long nr, long a, long b, long c, long d) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return x0;
}

enum { BLOCK_BYTES = 65536, TOTAL_CHUNKS = TARGET_TOTAL_CHUNKS, WINDOW_MAX = 128,
       PARTITIONS_LIMIT = 8192, MOUNTS_LIMIT = 32768,
       EXPECTED_KIB = TARGET_EXPECTED_KIB };
_Static_assert((unsigned long long)TOTAL_CHUNKS * BLOCK_BYTES ==
               (unsigned long long)EXPECTED_KIB * 1024ULL,
               "fixed size/chunk mismatch");
enum { AT_FDCWD = -100, O_RDONLY_CLOEXEC = 0x80000,
       O_RDONLY_CLOEXEC_NOFOLLOW = 0xa0000,
       O_WRONLY_CREATE_EXCL_CLOEXEC = 0x800c1,
       AT_REMOVEDIR = 0x200 };
enum { S_IFMT = 0170000, S_IFBLK = 0060000, S_IFREG = 0100000 };

/* arm64 Linux 4.9 asm-generic/stat.h syscall ABI, not a libc structure. */
struct kernel_stat {
    unsigned long st_dev, st_ino;
    unsigned int st_mode, st_nlink, st_uid, st_gid;
    unsigned long st_rdev, pad1;
    long st_size;
    int st_blksize, pad2;
    long st_blocks;
    long st_atime;
    unsigned long st_atime_nsec;
    long st_mtime;
    unsigned long st_mtime_nsec;
    long st_ctime;
    unsigned long st_ctime_nsec;
    unsigned int unused4, unused5;
};
_Static_assert(sizeof(struct kernel_stat) == 128, "arm64 kernel stat size");

static const char cmdline_path[] = "/proc/self/cmdline";
static const char partitions_path[] = "/proc/partitions";
static const char mounts_path[] = "/proc/mounts";
static const char tmpfs_path[] = "/tmp_wbshd";
static const char device_path[] = TARGET_DEVICE_PATH;
static const char preload_path[] = "/etc/ld.so.preload";
static const char request_path[] = TARGET_REQUEST_PATH;
static const char output_dir_prefix[] = TARGET_OUTPUT_PREFIX;
static const char expected_cmdline[] =
    "/bin/sh\0-c\0/bin/date -s 070421422017.26";

struct chunk_header {
    char magic[16];
    u32 version;
    u32 partition;
    u64 offset;
    u64 partition_bytes;
    u32 requested;
    u32 actual;
    u32 crc32;
    s32 status;
    u64 nonce;
    u32 selected_major;
    u32 selected_minor;
    char selected_name[16];
    u32 candidate_count;
    u32 reserved;
    unsigned char capture_id[16];
    u32 window_index;
    u32 global_index;
    u64 reserved2;
};
_Static_assert(sizeof(struct chunk_header) == 128, "header wire size");
struct completion_manifest {
    char magic[16];
    u32 version;
    u32 partition;
    u64 partition_bytes;
    u32 chunk_bytes;
    u32 chunk_count;
    u32 produced_count;
    u32 full_crc32;
    u32 selected_major;
    u32 selected_minor;
    char selected_name[16];
    s32 status;
    u32 reserved;
    u64 nonce;
    u64 reserved2;
    unsigned char capture_id[16];
    u32 window_index;
    u32 window_start;
    u32 total_chunks;
    u32 reserved3;
};
_Static_assert(sizeof(struct completion_manifest) == 128, "manifest wire size");
struct window_request {
    char magic[16];
    unsigned char capture_id[16];
    u32 version;
    u32 partition;
    u32 window_index;
    u32 window_start;
    u32 window_count;
    u32 chunk_bytes;
    u32 header_crc32;
    u32 reserved;
};
_Static_assert(sizeof(struct window_request) == 64, "request wire size");
struct partition_candidate {
    u32 major;
    u32 minor;
    char name[16];
};
static unsigned char partition_text[PARTITIONS_LIMIT];
static unsigned char mounts_text[MOUNTS_LIMIT];
static unsigned char block[BLOCK_BYTES];

static int is_space(unsigned char c);

static u32 device_major(u64 dev) {
    return (u32)(((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000));
}

static u32 device_minor(u64 dev) {
    return (u32)((dev & 0xff) | ((dev >> 12) & 0xffffff00));
}

static int token_equals(const unsigned char *begin, const unsigned char *end,
                        const char *literal) {
    const unsigned char *p = begin;
    for (usize i = 0; literal[i]; ++i) {
        if (p == end || *p++ != (unsigned char)literal[i]) return 0;
    }
    return p == end;
}

static int exact_tmpfs_mount(void) {
    unsigned long statfs_data[32] = {0};
    if (sc4(43, (long)tmpfs_path, (long)statfs_data, 0, 0) != 0 ||
        statfs_data[0] != 0x01021994UL) return 0; /* TMPFS_MAGIC */
    long fd = sc4(56, AT_FDCWD, (long)mounts_path, O_RDONLY_CLOEXEC, 0);
    if (fd < 0) return 0;
    usize used = 0;
    int eof = 0;
    while (used < MOUNTS_LIMIT) {
        long n = sc4(63, fd, (long)(mounts_text + used), MOUNTS_LIMIT - used, 0);
        if (n <= 0) { eof = (n == 0); break; }
        used += (usize)n;
    }
    sc4(57, fd, 0, 0, 0);
    if (!eof) return 0;
    const unsigned char *end = mounts_text + used;
    const unsigned char *line = mounts_text;
    while (line < end) {
        const unsigned char *next = line;
        while (next < end && *next != '\n') ++next;
        if (next == end) break;
        const unsigned char *p = line;
        for (int field = 0; field < 3; ++field) {
            while (p < next && is_space(*p)) ++p;
            const unsigned char *begin = p;
            while (p < next && !is_space(*p)) ++p;
            if (field == 1 && !token_equals(begin, p, "/tmp_wbshd")) break;
            if (field == 2 && token_equals(begin, p, "tmpfs")) return 1;
        }
        line = next + 1;
    }
    return 0;
}

static int exact_debug_child(void) {
    char cmd[96] = {0};
    long fd = sc4(56, AT_FDCWD, (long)cmdline_path, O_RDONLY_CLOEXEC, 0);
    if (fd < 0) return 0;
    long count = 0;
    int eof = 0;
    while (count < (long)sizeof(cmd)) {
        long n = sc4(63, fd, (long)(cmd + count), sizeof(cmd) - count, 0);
        if (n <= 0) { eof = (n == 0); break; }
        count += n;
    }
    sc4(57, fd, 0, 0, 0);
    if (!eof || count != (long)sizeof(expected_cmdline)) return 0;
    for (usize i = 0; i < sizeof(expected_cmdline); ++i)
        if (cmd[i] != expected_cmdline[i]) return 0;
    return 1;
}

static int is_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

static int parse_decimal(const unsigned char **cursor,
                         const unsigned char *end, u64 *out) {
    const unsigned char *p = *cursor;
    u64 value = 0;
    if (p == end || *p < '0' || *p > '9') return 0;
    while (p < end && *p >= '0' && *p <= '9') {
        u32 digit = *p++ - '0';
        if (value > (~(u64)0 - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    *cursor = p;
    *out = value;
    return 1;
}

static void skip_space(const unsigned char **cursor,
                       const unsigned char *end) {
    while (*cursor < end && is_space(**cursor)) ++*cursor;
}

static int expected_partition_rows(struct partition_candidate out[2]) {
    long fd = sc4(56, AT_FDCWD, (long)partitions_path,
                  O_RDONLY_CLOEXEC, 0);
    if (fd < 0) return 0;
    usize used = 0;
    int eof = 0;
    while (used < PARTITIONS_LIMIT) {
        long n = sc4(63, fd, (long)(partition_text + used),
                     PARTITIONS_LIMIT - used, 0);
        if (n <= 0) { eof = (n == 0); break; }
        used += (usize)n;
    }
    sc4(57, fd, 0, 0, 0);
    if (!eof) return 0;
    const unsigned char *end = partition_text + used;
    const unsigned char *line = partition_text;
    int seen_p = 0, seen_c = 0;
    while (line < end) {
        const unsigned char *next = line;
        while (next < end && *next != '\n') ++next;
        if (next == end) break;
        const unsigned char *p = line;
        u64 major, minor, blocks;
        skip_space(&p, next);
        if (parse_decimal(&p, next, &major)) {
            skip_space(&p, next);
            if (parse_decimal(&p, next, &minor)) {
                skip_space(&p, next);
                if (parse_decimal(&p, next, &blocks)) {
                    skip_space(&p, next);
                    const unsigned char *name_begin = p;
                    while (p < next && !is_space(*p)) ++p;
                    int which = token_equals(name_begin, p, TARGET_P_NAME) ? 0 :
                                (!TARGET_WHOLE && token_equals(
                                    name_begin, p, TARGET_C_NAME)) ? 1 : -1;
                    if (which >= 0) {
                        skip_space(&p, next);
                        if (p != next || blocks != EXPECTED_KIB ||
                            major > 0xffffffffu || minor > 0xffffffffu ||
                            (which == 0 ? seen_p : seen_c)) return 0;
                        if (which == 0) seen_p = 1; else seen_c = 1;
                        out[which].major = (u32)major;
                        out[which].minor = (u32)minor;
                        const char *name = which == 0 ? TARGET_P_NAME : TARGET_C_NAME;
                        for (usize i = 0; i < 16; ++i) out[which].name[i] = 0;
                        for (usize i = 0; i < 15 && name[i]; ++i)
                            out[which].name[i] = name[i];
                    }
                }
            }
        }
        line = next + 1;
    }
    return seen_p && (TARGET_WHOLE || seen_c) &&
           out[0].major == 252 &&
           out[0].minor == (TARGET_WHOLE ? 0 : TARGET_PARTITION_ID) &&
           (TARGET_WHOLE || (out[1].major == 252 &&
                             out[1].minor == TARGET_PARTITION_ID + 128));
}

static u32 crc32_update(u32 crc, const unsigned char *data, u32 len) {
    for (u32 i = 0; i < len; ++i) {
        crc ^= data[i];
        for (u32 bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc;
}

static u32 crc32_block(const unsigned char *data, u32 len) {
    return crc32_update(0xffffffffu, data, len) ^ 0xffffffffu;
}

static int read_window_request(struct window_request *request) {
    long fd = sc4(56, AT_FDCWD, (long)request_path,
                  O_RDONLY_CLOEXEC_NOFOLLOW, 0);
    if (fd < 0) return 0;
    struct kernel_stat st;
    int valid = sc4(80, fd, (long)&st, 0, 0) == 0 &&
                (st.st_mode & S_IFMT) == S_IFREG && st.st_size == 64;
    usize done = 0;
    while (valid && done < sizeof(*request)) {
        long n = sc4(63, fd, (long)((unsigned char *)request + done),
                     sizeof(*request) - done, 0);
        if (n <= 0) { valid = 0; break; }
        done += (usize)n;
    }
    unsigned char extra = 0;
    if (valid && sc4(63, fd, (long)&extra, 1, 0) != 0) valid = 0;
    sc4(57, fd, 0, 0, 0);
    if (!valid) return 0;
    static const char magic[16] = "CXD" TARGET_TAG "REQV1";
    for (usize i = 0; i < 16; ++i)
        if (request->magic[i] != magic[i]) return 0;
    u32 index = request->window_index;
    u32 start = index * WINDOW_MAX;
    u32 count = start < TOTAL_CHUNKS ? TOTAL_CHUNKS - start : 0;
    if (count > WINDOW_MAX) count = WINDOW_MAX;
    if (request->version != 1 || request->partition != TARGET_PARTITION_ID ||
        index >= (TOTAL_CHUNKS + WINDOW_MAX - 1) / WINDOW_MAX ||
        request->window_start != start || request->window_count != count ||
        request->chunk_bytes != BLOCK_BYTES || request->reserved != 0 ||
        request->header_crc32 !=
            crc32_block((const unsigned char *)request, 56)) return 0;
    int any = 0;
    for (usize i = 0; i < 16; ++i) any |= request->capture_id[i];
    return any != 0;
}

static int enough_tmpfs_for_remaining(const struct window_request *request) {
    unsigned long fs[32] = {0};
    if (sc4(43, (long)tmpfs_path, (long)fs, 0, 0) != 0 ||
        fs[0] != 0x01021994UL || fs[1] == 0 || fs[1] > 1048576UL)
        return 0;
    /* At most one current window survives after previous-window cleanup. */
    u64 needed = 52428800ULL +
                 (u64)request->window_count * BLOCK_BYTES + 2097152ULL;
    return fs[4] >= (needed + fs[1] - 1) / fs[1];
}

static void output_directory(char out[112], const struct window_request *request) {
    usize at = 0;
    for (usize i = 0; output_dir_prefix[i]; ++i)
        out[at++] = output_dir_prefix[i];
    static const char hex[] = "0123456789abcdef";
    for (usize i = 0; i < 16; ++i) {
        out[at++] = hex[request->capture_id[i] >> 4];
        out[at++] = hex[request->capture_id[i] & 15];
    }
    out[at++] = '_';
    out[at++] = 'w';
    char reversed[10];
    u32 value = request->window_index;
    usize digits = 0;
    do {
        reversed[digits++] = '0' + value % 10;
        value /= 10;
    } while (value && digits < sizeof(reversed));
    while (digits) out[at++] = reversed[--digits];
    out[at++] = '_';
    out[at++] = '2';
    out[at++] = '0';
    out[at++] = '1';
    out[at] = 0;
}

static int write_all(long fd, const void *src, usize count) {
    const unsigned char *p = (const unsigned char *)src;
    usize done = 0;
    while (done < count) {
        long n = sc4(64, fd, (long)(p + done), count - done, 0);
        if (n <= 0) return 0;
        done += (usize)n;
    }
    return 1;
}

static void chunk_filename(char out[128], const char directory[112], u32 local) {
    usize at = 0;
    for (usize i = 0; directory[i]; ++i) out[at++] = directory[i];
    static const char prefix[] = "/chunk_";
    for (usize i = 0; i < sizeof(prefix) - 1; ++i) out[at++] = prefix[i];
    static const char hex[] = "0123456789abcdef";
    out[at++] = hex[(local >> 4) & 15];
    out[at++] = hex[local & 15];
    static const char suffix[] = ".bin";
    for (usize i = 0; i < sizeof(suffix) - 1; ++i) out[at++] = suffix[i];
    out[at] = 0;
}

static void manifest_filename(char out[128], const char directory[112]) {
    usize at = 0;
    for (usize i = 0; directory[i]; ++i) out[at++] = directory[i];
    static const char suffix[] = "/manifest.bin";
    for (usize i = 0; i < sizeof(suffix) - 1; ++i) out[at++] = suffix[i];
    out[at] = 0;
}

static int remove_previous_window(const struct window_request *request) {
    if (request->window_index == 0) return 1;
    struct window_request previous = *request;
    --previous.window_index;
    char directory[112];
    output_directory(directory, &previous);
    u32 start = previous.window_index * WINDOW_MAX;
    u32 count = TOTAL_CHUNKS - start;
    if (count > WINDOW_MAX) count = WINDOW_MAX;
    for (u32 local = 0; local < count; ++local) {
        char path[128];
        chunk_filename(path, directory, local);
        if (sc4(35, AT_FDCWD, (long)path, 0, 0) != 0) return 0;
    }
    char manifest[128];
    manifest_filename(manifest, directory);
    if (sc4(35, AT_FDCWD, (long)manifest, 0, 0) != 0 ||
        sc4(35, AT_FDCWD, (long)directory, AT_REMOVEDIR, 0) != 0) return 0;
    return 1;
}

__attribute__((constructor))
static void owner_fixed_window_snapshot(void) {
    if (!exact_debug_child()) return;
    if (sc4(35, AT_FDCWD, (long)preload_path, 0, 0) != 0) {
        sc4(94, 78, 0, 0, 0);
        __builtin_unreachable();
    }
    if (!exact_tmpfs_mount()) {
        sc4(94, 77, 0, 0, 0);
        __builtin_unreachable();
    }
    struct window_request request = {0};
    if (!read_window_request(&request)) {
        sc4(94, 76, 0, 0, 0);
        __builtin_unreachable();
    }
    struct partition_candidate candidates[2] = {0};
    if (!expected_partition_rows(candidates)) {
        sc4(94, 75, 0, 0, 0);
        __builtin_unreachable();
    }
    long source = sc4(56, AT_FDCWD, (long)device_path,
                      O_RDONLY_CLOEXEC_NOFOLLOW, 0);
    if (source < 0) {
        sc4(94, 74, 0, 0, 0);
        __builtin_unreachable();
    }
    struct kernel_stat st;
    if (sc4(80, source, (long)&st, 0, 0) != 0 ||
        (st.st_mode & S_IFMT) != S_IFBLK) {
        sc4(57, source, 0, 0, 0);
        sc4(94, 73, 0, 0, 0);
        __builtin_unreachable();
    }
    u32 opened_major = device_major((u64)st.st_rdev);
    u32 opened_minor = device_minor((u64)st.st_rdev);
    if (opened_major != 252 || opened_minor != TARGET_MINOR ||
        candidates[TARGET_WHOLE ? 0 : 1].major != opened_major ||
        candidates[TARGET_WHOLE ? 0 : 1].minor != opened_minor) {
        sc4(57, source, 0, 0, 0);
        sc4(94, 72, 0, 0, 0); /* reject the pn view */
        __builtin_unreachable();
    }
    u64 actual_size = 0;
    if (sc4(29, source, 0x80081272, (long)&actual_size, 0) != 0 ||
        actual_size != (u64)TOTAL_CHUNKS * BLOCK_BYTES) {
        sc4(57, source, 0, 0, 0);
        sc4(94, 71, 0, 0, 0);
        __builtin_unreachable();
    }
    if (!remove_previous_window(&request)) {
        sc4(57, source, 0, 0, 0);
        sc4(94, 66, 0, 0, 0);
        __builtin_unreachable();
    }
    if (!enough_tmpfs_for_remaining(&request)) {
        sc4(57, source, 0, 0, 0);
        sc4(94, 67, 0, 0, 0);
        __builtin_unreachable();
    }
    char directory[112];
    output_directory(directory, &request);
    if (sc4(34, AT_FDCWD, (long)directory, 0700, 0) != 0) {
        sc4(57, source, 0, 0, 0);
        sc4(94, 70, 0, 0, 0); /* one capture/window per tmpfs lifetime */
        __builtin_unreachable();
    }

    u32 window_crc_state = 0xffffffffu;
    u32 produced = 0;
    s32 status = 0;
    for (u32 local = 0; local < request.window_count; ++local) {
        u32 global = request.window_start + local;
        u64 offset = (u64)global * BLOCK_BYTES;
        u32 obtained = 0;
        while (obtained < BLOCK_BYTES) {
            long n = sc4(67, source, (long)(block + obtained),
                         BLOCK_BYTES - obtained, offset + obtained);
            if (n <= 0) {
                status = n == 0 ? -5 : (s32)n;
                break;
            }
            obtained += (u32)n;
        }
        if (status != 0) break;
        struct chunk_header h = {
            .version = 1, .partition = TARGET_PARTITION_ID, .offset = offset,
            .partition_bytes = (u64)TOTAL_CHUNKS * BLOCK_BYTES,
            .requested = BLOCK_BYTES,
            .actual = BLOCK_BYTES, .crc32 = crc32_block(block, BLOCK_BYTES),
            .status = 0,
            .nonce = 0xa7c2102000001000ULL +
                     (u64)TARGET_PARTITION_ID * 0x10000ULL + global,
            .selected_major = opened_major, .selected_minor = opened_minor,
            .candidate_count = TARGET_WHOLE ? 1 : 2,
            .window_index = request.window_index,
            .global_index = global
        };
        static const char chunk_magic[16] = "CXD" TARGET_TAG "CHUNKV1";
        for (usize i = 0; i < 16; ++i) {
            h.magic[i] = chunk_magic[i];
            h.selected_name[i] = candidates[TARGET_WHOLE ? 0 : 1].name[i];
            h.capture_id[i] = request.capture_id[i];
        }
        char name[128];
        chunk_filename(name, directory, local);
        long output = sc4(56, AT_FDCWD, (long)name,
                          O_WRONLY_CREATE_EXCL_CLOEXEC, 0600);
        if (output < 0) { status = (s32)output; break; }
        int written = write_all(output, &h, sizeof(h)) &&
                      write_all(output, block, BLOCK_BYTES);
        sc4(57, output, 0, 0, 0);
        if (!written) { status = -80; break; }
        window_crc_state = crc32_update(window_crc_state, block, BLOCK_BYTES);
        ++produced;
    }
    sc4(57, source, 0, 0, 0);
    struct completion_manifest m = {
        .version = 1, .partition = TARGET_PARTITION_ID,
        .partition_bytes = (u64)TOTAL_CHUNKS * BLOCK_BYTES,
        .chunk_bytes = BLOCK_BYTES, .chunk_count = request.window_count,
        .produced_count = produced,
        .full_crc32 = window_crc_state ^ 0xffffffffu,
        .selected_major = opened_major, .selected_minor = opened_minor,
        .status = status,
        .nonce = 0xa7c210200000f000ULL +
                 (u64)TARGET_PARTITION_ID * 0x10000ULL + request.window_index,
        .window_index = request.window_index,
        .window_start = request.window_start,
        .total_chunks = TOTAL_CHUNKS
    };
    static const char manifest_magic[16] = "CXD" TARGET_TAG "WINMAN1";
    for (usize i = 0; i < 16; ++i) {
        m.magic[i] = manifest_magic[i];
        m.selected_name[i] = candidates[TARGET_WHOLE ? 0 : 1].name[i];
        m.capture_id[i] = request.capture_id[i];
    }
    char manifest_name[128];
    manifest_filename(manifest_name, directory);
    long manifest = sc4(56, AT_FDCWD, (long)manifest_name,
                        O_WRONLY_CREATE_EXCL_CLOEXEC, 0600);
    if (manifest < 0) {
        sc4(94, 69, 0, 0, 0);
        __builtin_unreachable();
    }
    int wrote_manifest = write_all(manifest, &m, sizeof(m));
    sc4(57, manifest, 0, 0, 0);
    sc4(94, wrote_manifest && status == 0 &&
            produced == request.window_count ? 0 : 68, 0, 0, 0);
    __builtin_unreachable();
}
