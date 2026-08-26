//
//  KFLogFilter.h
//  Kernel log filter — extracts readable, representative short lines
//
//  Four backends (selected at init, in priority order):
//    SYSCTL — sysctl(KERN_MSGBUF) direct snapshot copy. Only needs
//             sandbox escape (MAC policy patched) or msgbuf-read entitlement.
//    KRW    — kreadbuf() from kernel msgbuf ring. Needs full exploit +
//             init_xpf resolved _msgbufp/_msgbufsize.
//    SCAN   — kread64 scan memory for msgbuf structure. Needs Phase 1 exploit
//             (kread64 primitive) but NOT XPF/vnode offsets — robust on
//             devices where KRW backend's hardcoded offsets fail.
//    FILE   — /var/log/syslog and CrashReporter folder polling. Only needs
//             sandbox escape to walk paths outside app container.
//

#ifndef KFLOG_FILTER_H
#define KFLOG_FILTER_H

#include <stdbool.h>
#include <stdint.h>

// Max lines to keep in ring buffer
#define KFLOG_MAX_LINES     200
#define KFLOG_LINE_MAX      256

typedef enum {
    KFLOG_MODE_NONE = 0,
    KFLOG_MODE_SYSCTL = 1,  // stable syscall first; only needs sandbox escape
    KFLOG_MODE_KRW    = 2,  // kread64 from kernel msgbuf; full exploit + XPF
    KFLOG_MODE_FILE   = 3,  // /var/log file polling; only needs sandbox escape
    KFLOG_MODE_SCAN   = 4   // kread64 scan memory for msgbuf; full exploit, zero offsets
} KFLogMode;

typedef struct {
    char timestamp[6];      // "--:--" + null
    char tag[16];           // e.g. "[MEM]", "[SBX]"
    char text[128];         // short readable sentence
    int isRed;              // 1 = red text, 0 = normal white
} KFLogLine;

// Initialize filter and locate kernel msgbuf
typedef struct {
    KFLogMode mode;         // chosen backend
    uint64_t msgbuf_addr;   // (KRW/SCAN) kernel msgbuf virtual address
    uint64_t msgbuf_size;   // (KRW/SCAN) size of ring buffer
    uint64_t read_offset;   // (KRW/SCAN) last read position
    uint64_t last_head;     // (SCAN) last observed head pointer
    uint64_t last_tail;     // (SCAN) last observed tail pointer
    char   *snap_buf;       // (SYSCTL mode) last snapshot buffer
    size_t  snap_size;      // (SYSCTL mode) snapshot capacity
    size_t  snap_used;      // (SYSCTL mode) bytes valid in snap_buf
    size_t  snap_consumed;  // (SYSCTL mode) bytes already emitted to ring
    KFLogLine lines[KFLOG_MAX_LINES];
    int line_count;
    int line_head;          // ring buffer head
} KFLogFilter;

// Returns the backend that was chosen (or KFLOG_MODE_NONE if all failed).
KFLogMode KFLogInitFilter(KFLogFilter *filter);

// Return current backend mode as a human-readable string.
const char* KFLogModeName(KFLogMode mode);

// Current backend configured in this filter.
KFLogMode KFLogCurrentMode(const KFLogFilter *filter);

// Release resources held by the filter (snapshot buffer, etc.). Safe to
// call multiple times.
void KFLogDestroyFilter(KFLogFilter *filter);

// Poll msgbuf for new lines, return number of new lines found.
int KFLogPoll(KFLogFilter *filter);

// Get a line by index (0 = newest)
const KFLogLine* KFLogGetLine(KFLogFilter *filter, int index);

#endif
