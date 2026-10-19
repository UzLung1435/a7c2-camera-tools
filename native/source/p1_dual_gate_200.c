/* A7C II official 2.01 dual p1 gate template.
 * Only the checked .p1params ELF data section varies by body.
 */

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

enum { PATCH_BYTES = 45172, CHECKSUM_BYTES = 105, MOUNTS_LIMIT = 32768 };
enum { AT_FDCWD = -100, O_RDONLY_CLOEXEC = 0x80000,
       O_RDONLY_NOFOLLOW_CLOEXEC = 0xa0000,
       O_RDWR_NOFOLLOW_CLOEXEC = 0xa0002,
       O_RDWR_CREAT_EXCL_NOFOLLOW_CLOEXEC = 0xa00c2 };
enum { S_IFMT = 0170000, S_IFBLK = 0060000 };
enum { EXPECTED_MAJOR = 252, EXPECTED_MINOR = 129 };
enum { EXPECTED_PARTITION_BYTES = 25100288 };
#define PATCH_OFFSET (params.patch_offset)
static const u64 CHECKSUM_OFFSET = 16253440ULL;
static const u32 OLD_CRC = 0x2202e928U;
static const u64 OLD_FNV = 0xcbaab804803e18e8ULL;
static const u32 NEW_CRC = 0xf2ea309cU;
static const u64 NEW_FNV = 0x8bc9584a5f1b33c8ULL;

static const char cmdline_path[] = "/proc/self/cmdline";
static const char mounts_path[] = "/proc/mounts";
static const char tmpfs_path[] = "/tmp_wbshd";
static const char device_path[] = "/dev/cnflasha1";
static const char preload_path[] = "/etc/ld.so.preload";
#if defined(P1_VERIFY_ONLY) && defined(P1_RESTORE_ORIGINAL)
static const char status_path[] = "/tmp_wbshd/codex_p1_dual_gate_verify_patch_200.bin";
#elif defined(P1_VERIFY_ONLY)
static const char status_path[] = "/tmp_wbshd/codex_p1_dual_gate_verify_orig_200.bin";
#elif defined(P1_RESTORE_ORIGINAL)
static const char status_path[] = "/tmp_wbshd/codex_p1_dual_gate_restore_200.bin";
#else
static const char status_path[] = "/tmp_wbshd/codex_p1_dual_gate_writer_200.bin";
#endif
static const char expected_cmdline[] = "/bin/sh\0-c\0/bin/date -s 070421422017.26";
struct __attribute__((packed)) p1_params {
    char magic[16];
    u64 patch_offset;
    char old_checksum[CHECKSUM_BYTES];
    char new_checksum[CHECKSUM_BYTES];
    u32 crc;
};
_Static_assert(sizeof(struct p1_params) == 238, "p1 params ABI");
__attribute__((used, section(".p1params")))
static struct p1_params params = {
    .magic = "A7C2P1PARAM200",
    .patch_offset = 0x1122334455667788ULL,
    .old_checksum =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ./boot/vmlinux.bin\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  ./boot/initrd.img\n",
    .new_checksum =
        "cccccccccccccccccccccccccccccccc  ./boot/vmlinux.bin\n"
        "dddddddddddddddddddddddddddddddd  ./boot/initrd.img\n",
    .crc = 0,
};

#ifdef P1_RESTORE_ORIGINAL
#include "p1_frag40_original.h"
#define SOURCE_CRC NEW_CRC
#define SOURCE_FNV NEW_FNV
#define TARGET_CRC OLD_CRC
#define TARGET_FNV OLD_FNV
#define SOURCE_CHECKSUM params.new_checksum
#define TARGET_CHECKSUM params.old_checksum
#else
#include "p1_frag40_dual.h"
#define SOURCE_CRC OLD_CRC
#define SOURCE_FNV OLD_FNV
#define TARGET_CRC NEW_CRC
#define TARGET_FNV NEW_FNV
#define SOURCE_CHECKSUM params.old_checksum
#define TARGET_CHECKSUM params.new_checksum
#endif

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
_Static_assert(sizeof(struct kernel_stat) == 128, "AArch64 Linux stat ABI");
_Static_assert(sizeof(params.old_checksum) == CHECKSUM_BYTES, "old checksum size");
_Static_assert(sizeof(params.new_checksum) == CHECKSUM_BYTES, "new checksum size");
_Static_assert(sizeof(p1_patch_blob) == PATCH_BYTES, "patch blob size");

struct status_record {
    char magic[16];
    u32 version;
    u32 phase;
    s32 status;
    u32 rollback_verified;
    u32 selected_major;
    u32 selected_minor;
    u64 partition_bytes;
    u64 patch_offset;
    u32 patch_bytes;
    u32 source_crc;
    u32 target_crc;
    u32 reserved;
    u64 checksum_offset;
    u64 nonce;
};
_Static_assert(sizeof(struct status_record) == 88, "status wire size");

static unsigned char mounts_text[MOUNTS_LIMIT];
static unsigned char original_patch[PATCH_BYTES];
static unsigned char verify_patch[PATCH_BYTES];
static unsigned char verify_checksum[CHECKSUM_BYTES];
static struct status_record status_record = {
#if defined(P1_VERIFY_ONLY) && defined(P1_RESTORE_ORIGINAL)
    .magic = {'C','X','D','P','1','S','I','G','V','P','A','V','1',0,0,0},
#elif defined(P1_VERIFY_ONLY)
    .magic = {'C','X','D','P','1','S','I','G','V','O','R','V','1',0,0,0},
#elif defined(P1_RESTORE_ORIGINAL)
    .magic = {'C','X','D','P','1','S','I','G','R','S','T','V','1',0,0,0},
#else
    .magic = {'C','X','D','P','1','S','I','G','L','A','B','V','1',0,0,0},
#endif
    .version = 1, .phase = 0, .status = -1,
    .patch_offset = 0, .patch_bytes = PATCH_BYTES,
    .checksum_offset = 16253440ULL,
    .nonce =
#ifdef P1_RESTORE_ORIGINAL
        0xa7c2102000019912ULL
#else
        0xa7c2102000019911ULL
#endif
};
static long status_fd = -1;

static int equal(const void *a, const void *b, usize n) {
    const unsigned char *x = a, *y = b;
    for (usize i = 0; i < n; ++i) if (x[i] != y[i]) return 0;
    return 1;
}

static u32 crc32(const unsigned char *data, usize n) {
    u32 c = 0xffffffffU;
    for (usize i = 0; i < n; ++i) {
        c ^= data[i];
        for (int j = 0; j < 8; ++j)
            c = (c >> 1) ^ (0xedb88320U & (0U - (c & 1U)));
    }
    return c ^ 0xffffffffU;
}

static u64 fnv64(const unsigned char *data, usize n) {
    u64 h = 0xcbf29ce484222325ULL;
    for (usize i = 0; i < n; ++i) h = (h ^ data[i]) * 0x100000001b3ULL;
    return h;
}

static int valid_checksum(const char *p) {
    static const char kernel_tail[] = "  ./boot/vmlinux.bin\n";
    static const char initrd_tail[] = "  ./boot/initrd.img\n";
    for (int i = 0; i < 32; ++i) {
        unsigned char a = (unsigned char)p[i];
        unsigned char b = (unsigned char)p[53 + i];
        if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f'))
                || !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f'))) return 0;
    }
    return equal(p + 32, kernel_tail, 21) && equal(p + 85, initrd_tail, 20);
}

static int exact_io(long fd, unsigned char *buf, usize n, u64 at, int write_mode) {
    usize done = 0;
    while (done < n) {
        long got = sc4(write_mode ? 68 : 67, fd, (long)(buf + done),
                       (long)(n - done), (long)(at + done));
        if (got <= 0) return 0;
        done += (usize)got;
    }
    return 1;
}

static int exact_debug_child(void) {
    char cmd[sizeof(expected_cmdline)] = {0};
    long fd = sc4(56, AT_FDCWD, (long)cmdline_path, O_RDONLY_CLOEXEC, 0);
    if (fd < 0) return 0;
    usize n = 0;
    while (n < sizeof(cmd)) {
        long got = sc4(63, fd, (long)(cmd + n), sizeof(cmd) - n, 0);
        if (got <= 0) { sc4(57, fd, 0, 0, 0); return 0; }
        n += (usize)got;
    }
    char extra;
    long more = sc4(63, fd, (long)&extra, 1, 0);
    sc4(57, fd, 0, 0, 0);
    return more == 0 && equal(cmd, expected_cmdline, sizeof(cmd));
}

static int exact_tmpfs(void) {
    unsigned long statfs_data[32] = {0};
    return sc4(43, (long)tmpfs_path, (long)statfs_data, 0, 0) == 0
        && statfs_data[0] == 0x01021994UL;
}

static int p1_unmounted(void) {
    long fd = sc4(56, AT_FDCWD, (long)mounts_path, O_RDONLY_CLOEXEC, 0);
    if (fd < 0) return 0;
    usize n = 0;
    int eof = 0;
    while (n < MOUNTS_LIMIT) {
        long got = sc4(63, fd, (long)(mounts_text + n), MOUNTS_LIMIT - n, 0);
        if (got <= 0) { eof = (got == 0); break; }
        n += (usize)got;
    }
    sc4(57, fd, 0, 0, 0);
    if (!eof) return 0;
    const char *names[] = {"/dev/cnflasha1 ", "/dev/pnflasha1 ", "/dev/nflasha1 "};
    for (usize i = 0; i < n; ++i) {
        if (i != 0 && mounts_text[i - 1] != '\n') continue;
        for (int j = 0; j < 3; ++j) {
            usize k = 0;
            while (names[j][k] && i + k < n && mounts_text[i + k] == names[j][k]) ++k;
            if (names[j][k] == 0) return 0;
        }
    }
    return 1;
}

static u32 device_major(u64 dev) {
    return (u32)(((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000));
}
static u32 device_minor(u64 dev) {
    return (u32)((dev & 0xff) | ((dev >> 12) & 0xffffff00));
}

static int checkpoint(u32 phase, s32 code) {
    status_record.phase = phase;
    status_record.status = code;
    if (status_fd < 0) return 0;
    if (!exact_io(status_fd, (unsigned char *)&status_record,
                  sizeof(status_record), 0, 1)) return 0;
    return sc4(82, status_fd, 0, 0, 0) == 0;
}

static void finish(s32 code) {
    if (status_fd >= 0) sc4(57, status_fd, 0, 0, 0);
    sc4(94, code, 0, 0, 0);
    __builtin_unreachable();
}

__attribute__((constructor))
static void patch_p1_once(void) {
    if (!exact_debug_child()) return;
    if (sc4(35, AT_FDCWD, (long)preload_path, 0, 0) != 0)
        finish(78); /* never run the shell date command after failed unlink */
    if (!exact_tmpfs() || !p1_unmounted()) finish(77);
    if (!equal(params.magic, "A7C2P1PARAM200\0", 16)
            || params.crc == 0
            || crc32((const unsigned char *)&params, sizeof(params) - 4) != params.crc
            || params.patch_offset < 82432ULL
            || params.patch_offset > 82432ULL + 9519104ULL - PATCH_BYTES
            || !valid_checksum(params.old_checksum)
            || !valid_checksum(params.new_checksum)
            || !equal(params.old_checksum, params.new_checksum, 53)) finish(79);
    status_record.patch_offset = params.patch_offset;
    if (crc32(p1_patch_blob, PATCH_BYTES) != TARGET_CRC
            || fnv64(p1_patch_blob, PATCH_BYTES) != TARGET_FNV) finish(76);

    status_fd = sc4(56, AT_FDCWD, (long)status_path,
                    O_RDWR_CREAT_EXCL_NOFOLLOW_CLOEXEC, 0600);
    if (status_fd < 0) finish(75);
    if (!checkpoint(1, -1)) finish(74);
    long source = sc4(56, AT_FDCWD, (long)device_path,
#ifdef P1_VERIFY_ONLY
                      O_RDONLY_NOFOLLOW_CLOEXEC, 0);
#else
                      O_RDWR_NOFOLLOW_CLOEXEC, 0);
#endif
    if (source < 0) { checkpoint(1, -2); finish(74); }
    struct kernel_stat st;
    u64 capacity = 0;
    if (sc4(80, source, (long)&st, 0, 0) != 0
            || (st.st_mode & S_IFMT) != S_IFBLK
            || device_major(st.st_rdev) != EXPECTED_MAJOR
            || device_minor(st.st_rdev) != EXPECTED_MINOR
            || sc4(29, source, 0x80081272, (long)&capacity, 0) != 0
            || capacity != EXPECTED_PARTITION_BYTES) {
        checkpoint(1, -3); sc4(57, source, 0, 0, 0); finish(73);
    }
    status_record.selected_major = EXPECTED_MAJOR;
    status_record.selected_minor = EXPECTED_MINOR;
    status_record.partition_bytes = capacity;
    if (!checkpoint(2, -1)) {
        sc4(57, source, 0, 0, 0); finish(73);
    }

    if (!exact_io(source, original_patch, PATCH_BYTES, PATCH_OFFSET, 0)
            || crc32(original_patch, PATCH_BYTES) != SOURCE_CRC
            || fnv64(original_patch, PATCH_BYTES) != SOURCE_FNV
            || !exact_io(source, verify_checksum, CHECKSUM_BYTES, CHECKSUM_OFFSET, 0)
            || !equal(verify_checksum, SOURCE_CHECKSUM, CHECKSUM_BYTES)) {
        checkpoint(2, -4); sc4(57, source, 0, 0, 0); finish(72);
    }
    if (sc4(82, source, 0, 0, 0) != 0) {
        checkpoint(2, -8); sc4(57, source, 0, 0, 0); finish(70);
    }
    status_record.source_crc = SOURCE_CRC;
    if (!checkpoint(3, -1)) {
        sc4(57, source, 0, 0, 0); finish(71);
    }

#ifdef P1_VERIFY_ONLY
    if (!checkpoint(6, 0)) {
        sc4(57, source, 0, 0, 0); finish(71);
    }
    sc4(57, source, 0, 0, 0);
    finish(0);
#endif

    /* Critical section: all required original bytes are now in camera RAM. */
    int okay = exact_io(source, (unsigned char *)p1_patch_blob,
                        PATCH_BYTES, PATCH_OFFSET, 1);
    if (okay) okay = sc4(82, source, 0, 0, 0) == 0;
    if (okay) okay = exact_io(source, verify_patch, PATCH_BYTES, PATCH_OFFSET, 0);
    if (okay) okay = (crc32(verify_patch, PATCH_BYTES) == TARGET_CRC
                      && fnv64(verify_patch, PATCH_BYTES) == TARGET_FNV);
    if (okay) {
        status_record.target_crc = TARGET_CRC;
        okay = checkpoint(4, -1);
    }
    if (okay) {
        okay = exact_io(source, (unsigned char *)TARGET_CHECKSUM,
                        CHECKSUM_BYTES, CHECKSUM_OFFSET, 1);
        if (okay) okay = sc4(82, source, 0, 0, 0) == 0;
        if (okay) okay = exact_io(source, verify_checksum,
                                 CHECKSUM_BYTES, CHECKSUM_OFFSET, 0);
        if (okay) okay = equal(verify_checksum, TARGET_CHECKSUM, CHECKSUM_BYTES);
    }
    if (okay) {
        if (checkpoint(6, 0)) {
            sc4(57, source, 0, 0, 0);
            finish(0);
        }
    }

    checkpoint(7, -5);
    int rollback = exact_io(source, original_patch, PATCH_BYTES, PATCH_OFFSET, 1);
    rollback &= exact_io(source, (unsigned char *)SOURCE_CHECKSUM,
                         CHECKSUM_BYTES, CHECKSUM_OFFSET, 1);
    rollback &= sc4(82, source, 0, 0, 0) == 0;
    rollback &= exact_io(source, verify_patch, PATCH_BYTES, PATCH_OFFSET, 0);
    rollback &= exact_io(source, verify_checksum, CHECKSUM_BYTES, CHECKSUM_OFFSET, 0);
    rollback &= crc32(verify_patch, PATCH_BYTES) == SOURCE_CRC;
    rollback &= fnv64(verify_patch, PATCH_BYTES) == SOURCE_FNV;
    rollback &= equal(verify_checksum, SOURCE_CHECKSUM, CHECKSUM_BYTES);
    status_record.rollback_verified = rollback ? 1U : 0U;
    checkpoint(rollback ? 8 : 9, rollback ? -6 : -7);
    sc4(57, source, 0, 0, 0);
    finish(rollback ? 69 : 68);
}
