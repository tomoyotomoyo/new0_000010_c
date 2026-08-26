//
//  KFLogFilter.c
//  Kernel msgbuf reader — filters human-readable keywords, formats short lines
//
//  Three-backend architecture, priority ordered:
//    1) SYSCTL — sysctl(KERN_MSGBUF). Only needs sandbox escape (MAC patched).
//       Stable syscall, zero dependency on init_xpf/vnamecache offsets.
//       This is the "尽量走稳定 syscall 接口" route.
//    2) KRW    — kreadbuf() from kernel ring at _msgbufp. Full exploit chain
//       + init_xpf required. Only reached if sysctl fails.
//    3) FILE   — /var/log/syslog + CrashReporter file poll. Only needs
//       sandbox escape (read outside container). Fallback, captures new log
//       files written by syslogd, not the live kernel ring.
//

#include "KFLogFilter.h"

#include "../kexploit/krw.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#ifndef KERN_MSGBUF
#define KERN_MSGBUF 83
#endif

// === Externs for all backends =============================================
extern uint64_t g_msgbufp_addr;
extern uint64_t g_msgbuf_size;
extern uint64_t g_kernel_base;
__attribute__((weak)) void kreadbuf(uint64_t kaddr, void *buf, uint64_t len) {
    (void)kaddr; if (buf && len) memset(buf, 0, len);
}
__attribute__((weak)) uint64_t kread64(uint64_t kaddr) { (void)kaddr; return 0; }
__attribute__((weak)) uint32_t kread32(uint64_t kaddr) { (void)kaddr; return 0; }
__attribute__((weak)) bool is_kaddr_valid(uint64_t addr) { (void)addr; return false; }

// === Keyword tag table =====================================================
static struct {
    const char *keyword;
    const char *tag;
    int isRed;
} g_keywords[] = {
    {"pmap_enter",  "[MEM]", 0},
    {"pmap_remove", "[MEM]", 0},
    {"vm_fault",    "[MEM]", 0},
    {"vm_pageout",  "[MEM]", 0},
    {"vm_allocate", "[MEM]", 0},
    {"sandbox:",    "[SBX]", 1},
    {"Sandbox",     "[SBX]", 1},
    {"kext:",       "[KXT]", 0},
    {"com.apple.driver.", "[KXT]", 0},
    {"IOKit:",      "[IOK]", 0},
    {"AppleARMPE",  "[IOK]", 0},
    {"AppleA",      "[CPU]", 0},
    {"execve:",     "[EXE]", 0},
    {"fork",        "[EXE]", 0},
    {"exit",        "[EXE]", 0},
    {"syscall:",    "[SYS]", 0},
    {"cpu=",        "[CPU]", 0},
    {"thermal",     "[THR]", 0},
    {"wake",        "[PWR]", 0},
    {"sleep",       "[PWR]", 0},
    {"pmset",       "[PWR]", 0},
    {"panic",       "[ERR]", 1},
    {"BUG:",        "[ERR]", 1},
    {"assert",      "[ERR]", 1},
    {"failed",      "[ERR]", 1},
    {NULL, NULL, 0}
};

// === Public helpers ========================================================
const char* KFLogModeName(KFLogMode mode) {
    switch (mode) {
        case KFLOG_MODE_SYSCTL: return "SYSCTL";
        case KFLOG_MODE_KRW:    return "KRW";
        case KFLOG_MODE_FILE:   return "FILE";
        case KFLOG_MODE_SCAN:   return "SCAN";
        default:                return "NONE";
    }
}

KFLogMode KFLogCurrentMode(const KFLogFilter *filter) {
    return filter ? filter->mode : KFLOG_MODE_NONE;
}

void KFLogDestroyFilter(KFLogFilter *filter) {
    if (!filter) return;
    if (filter->snap_buf) {
        free(filter->snap_buf);
        filter->snap_buf = NULL;
    }
    filter->snap_size = 0;
    filter->snap_used = 0;
    filter->snap_consumed = 0;
    filter->mode = KFLOG_MODE_NONE;
}

// === Line formatter (shared by all backends) ==============================
static void format_line(const char *raw, KFLogLine *out) {
    memset(out, 0, sizeof(*out));
    out->isRed = 0;
    strncpy(out->tag, "[---]", sizeof(out->tag) - 1);

    const char *p = raw;
    if (*p == '[') {
        double ts = 0;
        if (sscanf(p, "[%lf]", &ts) == 1) {
            time_t t = (time_t)ts;
            struct tm *tm = localtime(&t);
            if (tm) {
                snprintf(out->timestamp, sizeof(out->timestamp), "%02d:%02d",
                         tm->tm_min, tm->tm_sec);
            }
            p = strchr(p, ']');
            if (p) p++;
            while (*p == ' ' || *p == '\t') p++;
        }
    }
    if (out->timestamp[0] == '\0') {
        strcpy(out->timestamp, "--:--");
    }
    for (int i = 0; g_keywords[i].keyword; i++) {
        if (strstr(raw, g_keywords[i].keyword)) {
            strncpy(out->tag, g_keywords[i].tag, sizeof(out->tag) - 1);
            out->isRed = g_keywords[i].isRed;
            break;
        }
    }
    const char *colon = strchr(p, ':');
    if (colon) {
        p = colon + 1;
        while (*p == ' ') p++;
    }
    int len = 0;
    while (*p && *p != '\n' && *p != '\r' && len < (int)sizeof(out->text) - 1) {
        out->text[len++] = *p++;
    }
    out->text[len] = '\0';
    if (out->text[0] == '\0') {
        strncpy(out->text, raw, sizeof(out->text) - 1);
    }
}

static void push_line(KFLogFilter *filter, const char *raw) {
    if (strlen(raw) < 10) return;
    KFLogLine entry;
    format_line(raw, &entry);
    if (strcmp(entry.tag, "[---]") == 0) return;
    filter->lines[filter->line_head] = entry;
    filter->line_head = (filter->line_head + 1) % KFLOG_MAX_LINES;
    if (filter->line_count < KFLOG_MAX_LINES) filter->line_count++;
}

// === Backend 1: SYSCTL =====================================================
// Ask kernel for current msgbuf size, then copy the whole ring buffer out
// into userland. The kernel returns the snapshot of the msgbuf ring
// (typically 4 MB), which we then walk line-by-line. On iOS 16.4+ this is
// blocked for apps without the com.apple.private.msgbuf-read entitlement,
// unless sandbox_escape() has patched the MAC policy.
static bool try_sysctl_backend(KFLogFilter *filter) {
    int mib[2] = { CTL_KERN, KERN_MSGBUF };

    // Step 1: size only (always allowed, even under sandbox).
    size_t sz = 0;
    if (sysctl(mib, 2, NULL, &sz, NULL, 0) != 0 || sz == 0) {
        printf("[KFLogFilter] SYSCTL: size query failed (errno=%d)\n", errno);
        return false;
    }
    // Clamp: typical XNU msgbuf is 256KB ~ 4MB; absurd sizes hint kernel bug.
    if (sz > 32 * 1024 * 1024) {
        printf("[KFLogFilter] SYSCTL: msgbuf size %zu too large, bailing\n", sz);
        return false;
    }

    // Step 2: try to copy the actual buffer. Will EPERM if sandbox is still
    // enforcing the msgbuf-read policy.
    char *buf = (char *)malloc(sz);
    if (!buf) return false;
    size_t used = sz;
    int r = sysctl(mib, 2, buf, &used, NULL, 0);
    if (r != 0) {
        printf("[KFLogFilter] SYSCTL: read failed (errno=%d sz=%zu). "
               "Sandbox still blocking msgbuf-read.\n", errno, sz);
        free(buf);
        return false;
    }
    if (used == 0 || used > sz) {
        free(buf);
        return false;
    }
    filter->snap_buf = buf;
    filter->snap_size = sz;
    filter->snap_used = used;
    filter->snap_consumed = 0;
    filter->mode = KFLOG_MODE_SYSCTL;
    printf("[KFLogFilter] SYSCTL backend OK — %zu bytes copied\n", used);
    return true;
}

// sysctl returns a *snapshot* of the whole ring each poll. We diff against
// the previous snapshot (byte-level, handling ring wrap) to find new bytes.
static int poll_sysctl(KFLogFilter *filter) {
    int mib[2] = { CTL_KERN, KERN_MSGBUF };
    size_t used = filter->snap_size;
    if (sysctl(mib, 2, filter->snap_buf, &used, NULL, 0) != 0) {
        // Failed mid-run: fall back to none mode so caller can retry later.
        printf("[KFLogFilter] SYSCTL: mid-run poll failed (errno=%d)\n", errno);
        return 0;
    }
    // Bytes added since last poll.
    size_t prev_used = filter->snap_used;
    filter->snap_used = used;

    // New data range: from `prev_used` to `used` in the snapshot. If the
    // kernel overwrote the ring we don't try to reconstruct — just emit
    // from start of snapshot.
    size_t start = (prev_used > 0 && used > prev_used) ? prev_used : 0;
    size_t end = used;
    if (start >= end) return 0;

    // Ensure NUL-terminated for line scanner.
    if (end < filter->snap_size) filter->snap_buf[end] = '\0';
    else filter->snap_buf[end - 1] = '\0';

    const char *base = filter->snap_buf;
    const char *p = base + start;
    const char *stop = base + end;
    int new_lines = 0;
    while (p < stop) {
        const char *nl = memchr(p, '\n', stop - p);
        const char *eol = nl ? nl : stop;
        size_t llen = (size_t)(eol - p);
        if (llen > 10 && llen < KFLOG_LINE_MAX) {
            char tmp[KFLOG_LINE_MAX];
            memcpy(tmp, p, llen);
            tmp[llen] = '\0';
            push_line(filter, tmp);
            new_lines++;
        }
        p = eol + 1;
    }
    return new_lines;
}

// === Backend 2: KRW (kernel memory) ========================================
static bool try_krw_backend(KFLogFilter *filter) {
    if (g_msgbufp_addr == 0 || g_msgbuf_size == 0) {
        printf("[KFLogFilter] KRW: _msgbufp/_msgbufsize not resolved by XPF\n");
        return false;
    }
    uint64_t addr = kread64(g_msgbufp_addr);
    uint64_t sz   = (uint64_t)kread32(g_msgbuf_size);
    if (addr == 0 || sz == 0) {
        printf("[KFLogFilter] KRW: kread *_msgbufp=0x%llx *_msgbufsize=0x%llx failed\n",
               (unsigned long long)addr, (unsigned long long)sz);
        return false;
    }
    filter->msgbuf_addr = addr;
    filter->msgbuf_size = sz;
    filter->read_offset = 0;
    filter->mode = KFLOG_MODE_KRW;
    printf("[KFLogFilter] KRW backend OK — addr=0x%llx size=0x%llx\n",
           (unsigned long long)addr, (unsigned long long)sz);
    return true;
}

static int poll_krw(KFLogFilter *filter) {
    if (filter->msgbuf_addr == 0 || filter->msgbuf_size == 0) return 0;
    char buf[4096];
    uint64_t offset = filter->read_offset % filter->msgbuf_size;
    uint64_t to_read = sizeof(buf) - 1;
    if (offset + to_read > filter->msgbuf_size) {
        to_read = filter->msgbuf_size - offset;
    }
    kreadbuf(filter->msgbuf_addr + offset, buf, to_read);
    buf[to_read] = '\0';

    int new_lines = 0;
    char *line = buf;
    char *next;
    while ((next = strchr(line, '\n')) != NULL) {
        *next = '\0';
        if (strlen(line) > 10) {
            push_line(filter, line);
            new_lines++;
        }
        size_t step = (size_t)(next - line) + 1;
        filter->read_offset += step;
        line = next + 1;
    }
    return new_lines;
}

// === Backend 3: SCAN (pure-read kread64 scan) ==============================
// Scan kernel memory for the msgbuf structure by finding _msgbufp pointer
// or by scanning for the msgbuf structure directly. Zero dependency on XPF
// or vname offsets — only uses the kread64 primitive established in Phase 1.
//
// The msgbuf structure layout (XNU 17-26):
//   +0:        mb_buf[S]   circular buffer of log text (S = MSG_BSIZE)
//   +S+0:      mb_magic1   uint32 magic
//   +S+8:      mb_size     uint64 (equals S)
//   +S+16:     mb_cur_size uint64
//   +S+24:     mb_max_size uint64
//   +S+32:     mb_head     uint64 (read pointer in buffer, 0..S-1)
//   +S+40:     mb_tail     uint64 (write pointer in buffer, 0..S-1)

static bool try_scan_backend(KFLogFilter *filter) {
    uint64_t kb = g_kernel_base;
    if (kb == 0) {
        printf("[KFLogFilter] SCAN: kernel_base is 0\n");
        return false;
    }

    uint64_t scan_start = kb - 0x02000000;
    uint64_t scan_end   = kb + 0x02000000;
    printf("[KFLogFilter] SCAN: scanning 0x%llx-0x%llx for msgbuf...\n",
           (unsigned long long)scan_start, (unsigned long long)scan_end);

    // Candidate msgbuf sizes (most common first)
    static const uint64_t SIZES[] = {4096, 16384, 32768, 65536};
    int n_sizes = (int)(sizeof(SIZES) / sizeof(SIZES[0]));

    // Batch buffer: 512 uint64s = 4KB per read
    uint64_t chunk[512];

    for (int si = 0; si < n_sizes; si++) {
        uint64_t S = SIZES[si];
        printf("[KFLogFilter] SCAN: trying size=%llu...\n",
               (unsigned long long)S);

        for (uint64_t cs = scan_start; cs < scan_end; cs += sizeof(chunk)) {
            if (!is_kaddr_valid(cs)) continue;
            kreadbuf(cs, chunk, sizeof(chunk));

            for (int i = 0; i < 512; i++) {
                if (chunk[i] != S) continue;

                // Found value S at cs + i*8 — potential mb_size field
                // msgbuf start = (cs + i*8) - (S + 8)
                uint64_t start = cs + (uint64_t)i * 8 - (S + 8);
                if (start < scan_start || start >= scan_end) continue;
                if (!is_kaddr_valid(start)) continue;

                // Verify head and tail are valid pointers within the buffer
                uint64_t head = kread64(start + S + 32);
                uint64_t tail = kread64(start + S + 40);
                if (head >= S || tail >= S || head == 0 || tail == 0) continue;

                // Verify the buffer contains printable log text
                uint64_t sample = kread64(start);
                unsigned char *b = (unsigned char *)&sample;
                int printable = 0;
                for (int j = 0; j < 8; j++) {
                    unsigned char c = b[j];
                    if ((c >= 0x20 && c < 0x7f) || c == '\n' ||
                        c == '\r' || c == '\t' || c == '\0') printable++;
                }
                if (printable < 3) continue;

                // FOUND
                filter->msgbuf_addr = start;
                filter->msgbuf_size = S;
                filter->read_offset = 0;
                filter->last_head = head;
                filter->last_tail = tail;
                filter->mode = KFLOG_MODE_SCAN;
                printf("[KFLogFilter] SCAN: FOUND msgbuf addr=0x%llx "
                       "size=%llu head=%llu tail=%llu\n",
                       (unsigned long long)start,
                       (unsigned long long)S,
                       (unsigned long long)head,
                       (unsigned long long)tail);
                return true;
            }
        }
    }

    printf("[KFLogFilter] SCAN: msgbuf not found in scan range\n");
    return false;
}

static int poll_scan(KFLogFilter *filter) {
    uint64_t sz = filter->msgbuf_size;
    uint64_t head = kread64(filter->msgbuf_addr + sz + 32);
    uint64_t tail = kread64(filter->msgbuf_addr + sz + 40);

    if (head == filter->last_head && tail == filter->last_tail) {
        return 0;
    }

    uint64_t old_tail = filter->last_tail;
    uint64_t new_tail = tail;

    // Calculate new data bytes between old_tail and new_tail
    uint64_t to_read;
    if (new_tail >= old_tail) {
        to_read = new_tail - old_tail;
    } else {
        to_read = (sz - old_tail) + new_tail;
    }
    if (to_read == 0 || to_read > 65535) {
        filter->last_head = head;
        filter->last_tail = tail;
        return 0;
    }

    // Read the data, handling ring wrap
    char buf[65536];
    if (old_tail + to_read <= sz) {
        kreadbuf(filter->msgbuf_addr + old_tail, buf, to_read);
    } else {
        uint64_t first = sz - old_tail;
        kreadbuf(filter->msgbuf_addr + old_tail, buf, first);
        kreadbuf(filter->msgbuf_addr, buf + first, to_read - first);
    }
    buf[to_read] = '\0';

    // Parse lines and push to ring buffer
    int new_lines = 0;
    char *line = buf;
    char *next;
    while ((next = strchr(line, '\n')) != NULL) {
        *next = '\0';
        if (strlen(line) > 10) {
            push_line(filter, line);
            new_lines++;
        }
        line = next + 1;
    }

    filter->last_head = head;
    filter->last_tail = tail;
    filter->read_offset = new_tail;
    return new_lines;
}

// === Backend 4: File polling (/var/log) ====================================
// Walk paths: /var/log/syslog, /var/mobile/Library/Logs/CrashReporter.
// Only needs sandbox escape (read outside container).
static const char *g_file_paths[] = {
    "/var/log/syslog",
    "/var/log/system.log",
    "/var/mobile/Library/Logs/CrashReporter",   // directory; we scan newest .ips
    NULL
};

static int64_t g_file_offsets[16]; // parallel to last N paths opened
static int     g_file_count = 0;

static bool try_file_backend(KFLogFilter *filter) {
    // Must be able to actually OPEN a file (not just stat it). stat() passes
    // without sandbox escape on iOS, but open() does not — so we'd otherwise
    // falsely advertise "FILE backend OK" while poll_file() silently returns 0.
    for (int i = 0; g_file_paths[i]; i++) {
        struct stat st;
        if (stat(g_file_paths[i], &st) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            int fd = open(g_file_paths[i], O_RDONLY);
            if (fd < 0) {
                printf("[KFLogFilter] FILE: %s stat-ok but open failed (errno=%d)\n",
                       g_file_paths[i], errno);
                continue;
            }
            close(fd);
            filter->mode = KFLOG_MODE_FILE;
            printf("[KFLogFilter] FILE backend OK — reading %s\n", g_file_paths[i]);
            return true;
        }

        if (S_ISDIR(st.st_mode)) {
            DIR *d = opendir(g_file_paths[i]);
            if (!d) {
                printf("[KFLogFilter] FILE: %s stat-ok but opendir failed (errno=%d)\n",
                       g_file_paths[i], errno);
                continue;
            }
            // Also verify we can read at least one entry.
            struct dirent *de = readdir(d);
            closedir(d);
            if (!de) {
                printf("[KFLogFilter] FILE: %s directory empty, skipping\n", g_file_paths[i]);
                continue;
            }
            filter->mode = KFLOG_MODE_FILE;
            printf("[KFLogFilter] FILE backend OK — scanning %s\n", g_file_paths[i]);
            return true;
        }
    }
    printf("[KFLogFilter] FILE: no readable /var/log paths (sandbox still on)\n");
    return false;
}

static int poll_file(KFLogFilter *filter) {
    (void)filter;
    int new_lines = 0;
    for (int i = 0; g_file_paths[i]; i++) {
        struct stat st;
        if (stat(g_file_paths[i], &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            DIR *d = opendir(g_file_paths[i]);
            if (!d) continue;
            // Scan newest .ips file; read lines we haven't seen yet.
            char newest[1024]; newest[0] = '\0';
            time_t newest_mtime = 0;
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                const char *name = de->d_name;
                size_t nl = strlen(name);
                if (nl < 5 || strcmp(name + nl - 4, ".ips") != 0) continue;
                char full[2048];
                snprintf(full, sizeof(full), "%s/%s", g_file_paths[i], name);
                struct stat fst;
                if (stat(full, &fst) != 0) continue;
                if (fst.st_mtime > newest_mtime) {
                    newest_mtime = fst.st_mtime;
                    strncpy(newest, full, sizeof(newest) - 1);
                }
            }
            closedir(d);
            if (newest[0] == '\0') continue;

            int fd = open(newest, O_RDONLY);
            if (fd < 0) continue;
            // Simple: read from g_file_offsets[i] to EOF, push new lines.
            if (g_file_count <= i) g_file_count = i + 1;
            off_t off = (off_t)g_file_offsets[i];
            if (off > 0 && lseek(fd, off, SEEK_SET) == (off_t)-1) { close(fd); continue; }
            char buf[4096];
            ssize_t n;
            char linebuf[KFLOG_LINE_MAX];
            int lp = 0;
            while ((n = read(fd, buf, sizeof(buf))) > 0) {
                for (ssize_t k = 0; k < n; k++) {
                    char c = buf[k];
                    if (c == '\n' || c == '\r') {
                        if (lp > 10) {
                            linebuf[lp] = '\0';
                            push_line(filter, linebuf);
                            new_lines++;
                        }
                        lp = 0;
                    } else if (lp < (int)sizeof(linebuf) - 1) {
                        linebuf[lp++] = c;
                    }
                }
            }
            off_t cur = lseek(fd, 0, SEEK_CUR);
            if (cur > 0) g_file_offsets[i] = (int64_t)cur;
            close(fd);
        } else if (S_ISREG(st.st_mode)) {
            // Regular /var/log/syslog style file.
            int fd = open(g_file_paths[i], O_RDONLY);
            if (fd < 0) continue;
            if (g_file_count <= i) g_file_count = i + 1;
            off_t off = (off_t)g_file_offsets[i];
            if (off > 0 && lseek(fd, off, SEEK_SET) == (off_t)-1) { close(fd); continue; }
            char buf[4096];
            ssize_t n;
            char linebuf[KFLOG_LINE_MAX];
            int lp = 0;
            while ((n = read(fd, buf, sizeof(buf))) > 0) {
                for (ssize_t k = 0; k < n; k++) {
                    char c = buf[k];
                    if (c == '\n' || c == '\r') {
                        if (lp > 10) {
                            linebuf[lp] = '\0';
                            push_line(filter, linebuf);
                            new_lines++;
                        }
                        lp = 0;
                    } else if (lp < (int)sizeof(linebuf) - 1) {
                        linebuf[lp++] = c;
                    }
                }
            }
            off_t cur = lseek(fd, 0, SEEK_CUR);
            if (cur > 0) g_file_offsets[i] = (int64_t)cur;
            close(fd);
        }
    }
    return new_lines;
}

// === Public init/poll APIs ================================================
KFLogMode KFLogInitFilter(KFLogFilter *filter) {
    memset(filter, 0, sizeof(*filter));

    // Priority 1: SYSCTL. If sandbox_escape has already run or device is
    // configured to allow msgbuf-read, this works without ANY exploit.
    if (try_sysctl_backend(filter)) return filter->mode;

    // Priority 2: KRW. Needs full exploit + init_xpf + vnode offsets (the
    // route that was crashing on A18 / iOS 18.4.1 before graceful degrade).
    if (try_krw_backend(filter)) return filter->mode;

    // Priority 3: SCAN. Pure-read kread64 scan for msgbuf structure.
    // Needs Phase 1 exploit (kread64) but NOT XPF/vnode offsets — robust
    // on A18 devices where KRW backend's hardcoded offsets fail.
    if (try_scan_backend(filter)) return filter->mode;

    // Priority 4: FILE. If sandbox_escape() has been applied, we can walk
    // /var/log outside the app container and tail the log files there.
    if (try_file_backend(filter)) return filter->mode;

    return KFLOG_MODE_NONE;
}

int KFLogPoll(KFLogFilter *filter) {
    switch (filter->mode) {
        case KFLOG_MODE_SYSCTL: return poll_sysctl(filter);
        case KFLOG_MODE_KRW:    return poll_krw(filter);
        case KFLOG_MODE_SCAN:   return poll_scan(filter);
        case KFLOG_MODE_FILE:   return poll_file(filter);
        default:                return 0;
    }
}

const KFLogLine* KFLogGetLine(KFLogFilter *filter, int index) {
    if (index < 0 || index >= filter->line_count) return NULL;
    int pos = (filter->line_head - 1 - index + KFLOG_MAX_LINES) % KFLOG_MAX_LINES;
    return &filter->lines[pos];
}
