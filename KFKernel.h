//
//  KFKernel.h
//  KFKernel Universal Engine v1.0
//
//  Public C API — 38 functions across 8 modules.
//  Wraps FilzaJailedDS core capabilities for generic use.
//

#ifndef KFKERNEL_H
#define KFKERNEL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============ Module 1: Initialization ============

/// Execute the full exploit chain (kexploit + sandbox escape + root elevation).
/// Must be called before any other KFKernel function.
/// @return 0 on success, non-zero on failure
int KFInit(void);

/// Check if KFInit() has been successfully called and kernel R/W is available.
bool KFIsReady(void);

/// Cleanup kernel state and restore socket reference counts.
/// Call on app termination to prevent kernel panic. Safe to call multiple times.
void KFShutdown(void);

/// Set a progress callback invoked during KFInit(). Called from exploit thread.
/// Signature: void cb(const char *msg, const char *type)
/// type values: "dim" (step heading), "success" (step OK), "error" (step failed)
void KFSetProgressCallback(void (*cb)(const char *, const char *));

// ============ Module 2: Kernel R/W ============

uint8_t  KFKread8 (uint64_t kaddr);
uint16_t KFKread16(uint64_t kaddr);
uint32_t KFKread32(uint64_t kaddr);
uint64_t KFKread64(uint64_t kaddr);

void KFKwrite8 (uint64_t kaddr, uint8_t  val);
void KFKwrite16(uint64_t kaddr, uint16_t val);
void KFKwrite32(uint64_t kaddr, uint32_t val);
void KFKwrite64(uint64_t kaddr, uint64_t val);

/// Read arbitrary length buffer from kernel space.
void KFKreadBuf(uint64_t kaddr, void *buf, uint64_t len);

/// Write arbitrary length buffer to kernel space.
void KFKwriteBuf(uint64_t kaddr, const void *buf, uint64_t len);

/// Read a kernel pointer (handles PAC/SMR if needed).
uint64_t KFKreadPtr(uint64_t kaddr);

// ============ Module 3: Process Operations ============

/// Get the kernel address of the current process's proc struct.
uint64_t KFProcSelf(void);

/// Find a process by PID.
/// @return proc address or 0 if not found
uint64_t KFProcFindByPid(pid_t pid);

/// Find a process by name.
/// @return proc address or 0 if not found
uint64_t KFProcFindByName(const char *name);

// ============ Module 4: Filesystem (via kernel APFS) ============

/// Read a file using kernel R/W (bypasses sandbox).
/// @return bytes read, or -1 on error
ssize_t KFReadFile(const char *path, void *buf, size_t len);

/// Write a file using kernel R/W (bypasses sandbox + DAC).
/// @return bytes written, or -1 on error
ssize_t KFWriteFile(const char *path, const void *buf, size_t len);

/// Change file owner via kernel APFS node (bypasses uid check).
int KFChown(const char *path, uid_t uid, gid_t gid);

/// Change file mode via kernel APFS node.
int KFChmod(const char *path, mode_t mode);

/// Recursively chown a directory tree.
/// @return number of entries processed, or -1 on error
long KFChownTree(const char *root, uid_t uid, gid_t gid);

/// Redirect file access by swapping vnode pointers.
/// @return 0 on success, -1 on failure
int KFRedirectFile(const char *from, const char *to);

/// Restore original vnode.
int KFUnredirectFile(const char *path);

// ============ Module 5: IOKit Sensors ============

/// Set an IOKit service property (user-space API, requires entitlements).
int KFIOKitSetProperty(const char *service, const char *key, void *value, size_t len);

/// Get an IOKit service property.
int KFIOKitGetProperty(const char *service, const char *key, void *buf, size_t *len);

/// List matching IOKit services.
int KFIOKitListServices(const char *className, char **names, int maxCount);

/// Inject accelerometer data (theoretical, requires driver hook).
int KFInjectAccelerometer(double x, double y, double z);

/// Inject gyroscope data.
int KFInjectGyroscope(double x, double y, double z);

/// Inject magnetometer data.
int KFInjectMagnetometer(double x, double y, double z);

/// Inject barometer data.
int KFInjectBarometer(double pressure);

// ============ Module 6: Signature Bypass ============

/// Bypass CoreTrust for a Mach-O binary (uses ChOma engine).
int KFBypassCoreTrust(const char *path);

/// Forge entitlements blob for a binary.
int KFForgeEntitlements(const char *path, const char *entitlementsXML);

/// Calculate CDHash for a binary.
int KFCalculateCDHash(const char *path, uint8_t cdhash[32]);

// ============ Module 7: Kernel Call ============

/// Execute a kernel function with up to 8 arguments.
/// @param func Kernel function address
/// @param argc Number of arguments (0-8)
/// @return Kernel return value
uint64_t KFKcall(uint64_t func, int argc, ...);

// ============ Module 8: Device Info ============

/// Get supported iOS version range.
const char* KFSupportedVersions(void);

/// Check if current device is supported.
bool KFDeviceSupported(void);

/// Get device model string (e.g. "iPhone15,2").
const char* KFDeviceModel(void);

/// Check if device has A18 or newer chip.
bool KFIsA18Device(void);

/// Check if sandbox has been escaped.
bool KFIsSandboxEscaped(void);

/// Check if running as root (uid=0).
bool KFIsRoot(void);

// ============ Kernel Log Globals (set by XPF) ============

/// Runtime kernel VA of _msgbufp pointer variable (set by init_xpf).
extern uint64_t g_msgbufp_addr;

/// Runtime kernel VA of _msgbufsize variable (set by init_xpf).
extern uint64_t g_msgbuf_size;

// ============ Logging (internal) ============

/// Print a hex dump of kernel memory.
void KFHexdump(uint64_t kaddr, size_t size);

#ifdef __cplusplus
}
#endif

#endif // KFKERNEL_H
