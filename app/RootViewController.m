//
//  RootViewController.m
//  KFLog — AMA-10 terminal + staged exploit logging
//

#import "RootViewController.h"
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import "KFLogFilter.h"
#import "KFKernel.h"

@interface RootViewController () {
    WKWebView *_webView;
    NSTimer *_logTimer;
    KFLogFilter _filter;
    BOOL _exploitDone;
    BOOL _exploitRunning;      // guards against concurrent KFInit calls
    AVAudioPlayer *_silentPlayer;
    NSString *_pendingCrashLog; // displayed at start of runExploitStaged
}
@end

@implementation RootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    // --- Check for crash log from previous run (before FAILURE→exit) --------
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    NSString *crashPath = [docs stringByAppendingPathComponent:@"kflog_crash.log"];
    if ([fm fileExistsAtPath:crashPath]) {
        NSError *err = nil;
        NSString *content = [NSString stringWithContentsOfFile:crashPath
                                                       encoding:NSUTF8StringEncoding
                                                          error:&err];
        if (!err && content.length > 0) {
            _pendingCrashLog = [content copy];
        }
        [fm removeItemAtPath:crashPath error:nil];
    }

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    WKWebpagePreferences *wp = [[WKWebpagePreferences alloc] init];
    wp.allowsContentJavaScript = YES;
    cfg.defaultWebpagePreferences = wp;
    [cfg.userContentController addScriptMessageHandler:self name:@"kflog"];

    _webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:cfg];
    _webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _webView.navigationDelegate = self;
    _webView.backgroundColor = [UIColor blackColor];
    _webView.opaque = NO;
    [self.view addSubview:_webView];

    NSString *htmlPath = [[NSBundle mainBundle] pathForResource:@"index" ofType:@"html"];
    if (htmlPath) {
        NSURL *url = [NSURL fileURLWithPath:htmlPath];
        [_webView loadFileURL:url allowingReadAccessToURL:[url URLByDeletingLastPathComponent]];
    }

    [self startSilentAudio];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self runExploitStaged];
    });
}

- (void)dealloc {
    // Always tear down timer / player / JS handler when VC goes away.
    if (_logTimer) {
        [_logTimer invalidate];
        _logTimer = nil;
    }
    if (_silentPlayer) {
        [_silentPlayer stop];
        _silentPlayer = nil;
    }
    if (_webView) {
        [_webView.configuration.userContentController removeScriptMessageHandlerForName:@"kflog"];
    }
    // Release any snapshot buffer allocated by SYSCTL backend.
    KFLogDestroyFilter(&_filter);
    [super dealloc];
}

// MARK: - Staged Exploit Logging

// C callback trampoline — forwards progress messages to the Objective-C VC.
static void _kflog_progress_trampoline(const char *msg, const char *type) {
    if (!msg) return;
    // Dispatch to main thread; RootViewController is a lifetime singleton,
    // so calling +performSelector: is safe under MRC (no ARC involved).
    dispatch_async(dispatch_get_main_queue(), ^{
        // Find the RootViewController via the app's keyWindow.
        UIWindow *win = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                win = [(UIWindowScene *)scene windows].firstObject;
                break;
            }
        }
        if (!win) {
            // Fallback: use first window from keyWindow (pre-iOS 13 compat)
            win = [UIApplication sharedApplication].keyWindow;
        }
        RootViewController *vc = (RootViewController *)win.rootViewController;
        if (vc && [vc respondsToSelector:@selector(progressMsg:type:)]) {
            [vc progressMsg:[NSString stringWithUTF8String:msg]
                      type:[NSString stringWithUTF8String:type ? type : "dim"]];
        }
    });
}

- (void)progressMsg:(NSString *)msg type:(NSString *)type {
    [self boot:msg type:type];
}

- (void)runExploitStaged {
    // Defensive guard: never overlap two exploit attempts in flight.
    if (_exploitRunning) {
        [self boot:@"> Exploit already in progress, ignoring reinit" type:@"dim"];
        return;
    }

    [self jsEval:@"clearBoot();"];

    // --- Display last-run exploit failure log if any -----------------------
    if (_pendingCrashLog.length > 0) {
        NSArray *lines = [_pendingCrashLog componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            if (line.length == 0) continue;
            NSString *display = [NSString stringWithFormat:@"> [CRASH] %@", line];
            [self boot:display type:@"error"];
        }
        _pendingCrashLog = nil;
    }

    _exploitDone = NO;

    // Reset KFLogFilter state so reinit picks up a fresh msgbuf cursor.
    KFLogDestroyFilter(&_filter);
    memset(&_filter, 0, sizeof(_filter));

    // Stop previous log timer (will be restarted after successful setup)
    if (_logTimer) {
        [_logTimer invalidate];
        _logTimer = nil;
    }

    [self boot:@"> KFLog terminal initializing..." type:@"dim"];
    [self boot:@"> Audio keep-alive active" type:@"success"];

    // Install progress callback so KFInit streams each step as it happens.
    KFSetProgressCallback(_kflog_progress_trampoline);

    _exploitRunning = YES;
    // RootViewController is a process-lifetime singleton (window.rootViewController),
    // so capturing self in these short-lived dispatch blocks is safe under MRC.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            int ret = KFInit();

            dispatch_async(dispatch_get_main_queue(), ^{
                self->_exploitRunning = NO;

                if (ret == 0) {
                    self->_exploitDone = YES;

                    // === Collect system info now that sandbox is escaped ===
                    [self collectAndDisplaySystemInfo];

                    // === Init log channel (sysctl → KRW → FILE) ===
                    KFLogMode mode = KFLogInitFilter(&self->_filter);
                    if (mode != KFLOG_MODE_NONE) {
                        NSString *modeName = [NSString stringWithUTF8String:KFLogModeName(mode)];
                        [self boot:[NSString stringWithFormat:@"> Kernel log channel connected (%@)", modeName] type:@"success"];
                        [self setStatus:@"ok" text:[NSString stringWithFormat:@"LOGGING·%@", modeName]];
                        [self startLogStream];
                    } else {
                        [self boot:@"> Kernel log channel failed (fallback mode — R/W commands still work)" type:@"dim"];
                        [self setStatus:@"warn" text:@"FALLBACK"];
                    }
                } else {
                    [self boot:[NSString stringWithFormat:@"> EXPLOIT FAILED: %d", ret] type:@"error"];
                    [self setStatus:@"err" text:@"FAILED"];
                }
            });
        });
    });
}

// MARK: - System Info Collection

- (void)collectAndDisplaySystemInfo {
    // Device info
    NSString *model = [NSString stringWithUTF8String:KFDeviceModel()];
    char iosver[64] = {0};
    size_t ioslen = sizeof(iosver);
    sysctlbyname("kern.osversion", iosver, &ioslen, NULL, 0);
    BOOL isA18 = KFIsA18Device();

    [self boot:[NSString stringWithFormat:@"> Device: %@ | iOS %s | A18=%@",
                                                         model, iosver, isA18 ? @"yes" : @"no"] type:@"dim"];

    // Memory / uptime
    int64_t memsize = 0;
    size_t msz = sizeof(memsize);
    sysctlbyname("hw.memsize", &memsize, &msz, NULL, 0);
    int32_t uptime = 0;
    size_t usz = sizeof(uptime);
    sysctlbyname("kern.boottime", &uptime, &usz, NULL, 0);
    {
        long long memMB = memsize / (1024 * 1024);
        [self boot:[NSString stringWithFormat:@"> Memory: %lld MB | Uptime: %d sec | uid=%d",
                                                             memMB, uptime, getuid()] type:@"dim"];
    }

    // Recent crash logs (CrashReporter)
    NSString *crashDir = @"/var/mobile/Library/Logs/CrashReporter";
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:crashDir]) {
        NSError *err = nil;
        NSArray *files = [fm contentsOfDirectoryAtPath:crashDir error:&err];
        if (!err && files.count > 0) {
            NSPredicate *ipsPred = [NSPredicate predicateWithFormat:@"self ENDSWITH '.ips'"];
            NSArray *ipsFiles = [[files filteredArrayUsingPredicate:ipsPred] sortedArrayUsingSelector:@selector(compare:)];
            NSArray *recent = ipsFiles;
            if (recent.count > 5) recent = [recent subarrayWithRange:NSMakeRange(recent.count - 5, 5)];
            [self boot:[NSString stringWithFormat:@"> CrashReporter: %lu .ips files (newest: %@)",
                                                               (unsigned long)ipsFiles.count, ipsFiles.lastObject] type:@"dim"];
            // Tail the newest .ips file — show last 5 non-empty lines
            if (ipsFiles.count > 0) {
                NSString *newest = [crashDir stringByAppendingPathComponent:ipsFiles.lastObject];
                NSError *readErr = nil;
                NSString *content = [NSString stringWithContentsOfFile:newest
                                                              encoding:NSUTF8StringEncoding
                                                                 error:&readErr];
                if (!readErr && content.length > 0) {
                    NSArray *allLines = [content componentsSeparatedByString:@"\n"];
                    NSMutableArray *nonEmpty = [NSMutableArray array];
                    for (NSString *ln in allLines) {
                        if (ln.length > 2) [nonEmpty addObject:ln];
                    }
                    NSArray *last5 = nonEmpty.count > 5
                        ? [nonEmpty subarrayWithRange:NSMakeRange(nonEmpty.count - 5, 5)]
                        : nonEmpty;
                    [self boot:[NSString stringWithFormat:@"> Recent crash summary (from %@):", ipsFiles.lastObject] type:@"dim"];
                    for (NSString *ln in last5) {
                        NSString *trimmed = [ln stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                        if (trimmed.length > 0) {
                            [self boot:[NSString stringWithFormat:@">   %@", trimmed] type:@"dim"];
                        }
                    }
                }
            }
        } else if (err) {
            [self boot:[NSString stringWithFormat:@"> CrashReporter directory not readable: %@", err.localizedDescription] type:@"dim"];
        }
    } else {
        [self boot:@"> CrashReporter: /var/mobile/Library/Logs/CrashReporter not accessible" type:@"dim"];
    }

    // Syslog tail
    NSArray *syslogPaths = @[@"/var/log/syslog", @"/var/log/system.log"];
    for (NSString *path in syslogPaths) {
        if ([fm fileExistsAtPath:path]) {
            NSError *readErr = nil;
            NSString *content = [NSString stringWithContentsOfFile:path
                                                          encoding:NSUTF8StringEncoding
                                                             error:&readErr];
            if (!readErr && content.length > 0) {
                NSArray *allLines = [content componentsSeparatedByString:@"\n"];
                NSArray *last3 = allLines.count > 3
                    ? [allLines subarrayWithRange:NSMakeRange(allLines.count - 3, 3)]
                    : allLines;
                [self boot:[NSString stringWithFormat:@"> %@ (last %lu lines):", path.lastPathComponent, (unsigned long)last3.count] type:@"dim"];
                for (NSString *ln in last3) {
                    NSString *trimmed = [ln stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    if (trimmed.length > 0) {
                        [self boot:[NSString stringWithFormat:@">   %@", trimmed] type:@"dim"];
                    }
                }
                break;
            }
        }
    }

    // Top processes (via proc_find iteration — lightweight scan of common names)
    NSArray *interestingProcs = @[@"backboardd", @"mediaserverd", @"wifid", @"bluetoothd",
                                   @"symptomsd", @"powerd", @"systemstatsd", @"LocationServices",
                                   @"cloud", @"apsd", @"networkd"];
    NSMutableArray *foundProcs = [NSMutableArray array];
    for (NSString *pname in interestingProcs) {
        uint64_t p = KFProcFindByName([pname UTF8String]);
        if (p != 0) {
            [foundProcs addObject:[NSString stringWithFormat:@"%@(0x%llX)", pname, (unsigned long long)p]];
        }
    }
    if (foundProcs.count > 0) {
        [self boot:[NSString stringWithFormat:@"> Key processes: %@", [foundProcs componentsJoinedByString:@", "]] type:@"dim"];
    }
}

// MARK: - Log Stream

- (void)startLogStream {
    if (_logTimer) return;
    // RootViewController is a process-lifetime singleton; safe to retain self
    // directly. The timer is invalidated in dealloc and runExploitStaged.
    _logTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *timer) {
        [self pollLogs];
    }];
}

- (void)pollLogs {
    if (!_exploitDone) return;
    int n = KFLogPoll(&_filter);
    for (int i = n - 1; i >= 0; i--) {
        const KFLogLine *line = KFLogGetLine(&_filter, i);
        if (!line) continue;
        NSString *json = [NSString stringWithFormat:
            @"{\"t\":\"%s\",\"tag\":\"%s\",\"text\":\"%s\",\"r\":%d}",
            line->timestamp, line->tag, line->text, line->isRed];
        [self jsEval:[NSString stringWithFormat:@"addKernelLog(%@)", json]];
    }
}

// MARK: - JS Bridge

- (void)boot:(NSString *)text type:(NSString *)type {
    NSString *safe = [text stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    [self jsEval:[NSString stringWithFormat:@"addBootStep(\"%@\",\"%@\")", safe, type]];
}

- (void)setStatus:(NSString *)state text:(NSString *)text {
    [self jsEval:[NSString stringWithFormat:@"setStatus(\"%@\",\"%@\")", state, text]];
}

- (void)jsEval:(NSString *)script {
    [_webView evaluateJavaScript:script completionHandler:nil];
}

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"kflog"]) return;

    NSString *cmd = message.body;
    NSArray *parts = [cmd componentsSeparatedByString:@" "];
    NSString *op = parts.firstObject;

    // Kernel R/W commands
    if ([op isEqualToString:@"kr8"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint8_t v = KFKread8(addr);
        [self boot:[NSString stringWithFormat:@"> kr8(0x%llX) = 0x%02X", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kr16"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint16_t v = KFKread16(addr);
        [self boot:[NSString stringWithFormat:@"> kr16(0x%llX) = 0x%04X", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kr32"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint32_t v = KFKread32(addr);
        [self boot:[NSString stringWithFormat:@"> kr32(0x%llX) = 0x%08X", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kr64"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint64_t v = KFKread64(addr);
        [self boot:[NSString stringWithFormat:@"> kr64(0x%llX) = 0x%llX", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kw8"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint8_t v = (uint8_t)strtoul([parts[2] UTF8String], NULL, 0);
        KFKwrite8(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw8(0x%llX, 0x%02X) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"kw16"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint16_t v = (uint16_t)strtoul([parts[2] UTF8String], NULL, 0);
        KFKwrite16(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw16(0x%llX, 0x%04X) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"kw32"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint32_t v = (uint32_t)strtoul([parts[2] UTF8String], NULL, 0);
        KFKwrite32(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw32(0x%llX, 0x%08X) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"kw64"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint64_t v = strtoull([parts[2] UTF8String], NULL, 0);
        KFKwrite64(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw64(0x%llX, 0x%llX) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"khd"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        size_t sz = strtoul([parts[2] UTF8String], NULL, 0);
        KFHexdump(addr, sz);
        [self boot:[NSString stringWithFormat:@"> hexdump(0x%llX, %zu) printed to stdout", addr, sz] type:@"dim"];
    }
    else if ([op isEqualToString:@"proc"] && parts.count >= 2) {
        NSString *procName = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)] componentsJoinedByString:@" "];
        const char *name = [procName UTF8String];
        uint64_t p = KFProcFindByName(name);
        [self boot:[NSString stringWithFormat:@"> proc_find(\"%s\") = 0x%llX", name, p] type:p ? @"success" : @"error"];
    }
    else if ([op isEqualToString:@"chown"] && parts.count >= 4) {
        const char *path = [parts[1] UTF8String];
        uid_t uid = (uid_t)atoi([parts[2] UTF8String]);
        gid_t gid = (gid_t)atoi([parts[3] UTF8String]);
        int r = KFChown(path, uid, gid);
        [self boot:[NSString stringWithFormat:@"> chown(\"%s\", %d, %d) = %d", path, uid, gid, r] type:r == 0 ? @"success" : @"error"];
    }
    else if ([op isEqualToString:@"chmod"] && parts.count >= 3) {
        const char *path = [parts[1] UTF8String];
        mode_t mode = (mode_t)strtoul([parts[2] UTF8String], NULL, 8);
        int r = KFChmod(path, mode);
        [self boot:[NSString stringWithFormat:@"> chmod(\"%s\", 0%o) = %d", path, mode, r] type:r == 0 ? @"success" : @"error"];
    }
    else if ([cmd isEqualToString:@"start"]) {
        [self startLogStream];
    }
    else if ([cmd isEqualToString:@"stop"]) {
        if (_logTimer) {
            [_logTimer invalidate];
            _logTimer = nil;
        }
    }
    else if ([cmd isEqualToString:@"reinit"]) {
        [self runExploitStaged];
    }
    else if ([cmd isEqualToString:@"clear"]) {
        [self jsEval:@"clearBoot();clearKernel();"];
    }
}

// MARK: - Background Audio

- (void)startSilentAudio {
    // Idempotent: if a player is already running, leave it alone.
    if (_silentPlayer && _silentPlayer.isPlaying) return;
    if (_silentPlayer) {
        [_silentPlayer stop];
        _silentPlayer = nil;
    }

    uint8_t wav[44 + 44100 * 2] = {0};
    memcpy(wav, "RIFF", 4);
    uint32_t chunkSize = 36 + 44100 * 2;
    memcpy(wav + 4, &chunkSize, 4);
    memcpy(wav + 8, "WAVE", 4);
    memcpy(wav + 12, "fmt ", 4);
    uint32_t subchunk1 = 16;
    memcpy(wav + 16, &subchunk1, 4);
    uint16_t audioFormat = 1;
    memcpy(wav + 20, &audioFormat, 2);
    uint16_t numChannels = 1;
    memcpy(wav + 22, &numChannels, 2);
    uint32_t sampleRate = 44100;
    memcpy(wav + 24, &sampleRate, 4);
    uint32_t byteRate = 44100 * 2;
    memcpy(wav + 28, &byteRate, 4);
    uint16_t blockAlign = 2;
    memcpy(wav + 32, &blockAlign, 2);
    uint16_t bitsPerSample = 16;
    memcpy(wav + 34, &bitsPerSample, 2);
    memcpy(wav + 36, "data", 4);
    uint32_t dataSize = 44100 * 2;
    memcpy(wav + 40, &dataSize, 4);

    NSData *data = [NSData dataWithBytes:wav length:sizeof(wav)];
    NSError *err = nil;
    _silentPlayer = [[AVAudioPlayer alloc] initWithData:data error:&err];
    if (err) {
        NSLog(@"[KFLog] AVAudioPlayer init failed: %@", err);
        return;
    }
    _silentPlayer.volume = 0.0;
    _silentPlayer.numberOfLoops = -1;
    BOOL ok = [_silentPlayer play];
    if (!ok) {
        NSLog(@"[KFLog] AVAudioPlayer play returned NO");
    }
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    _webView.frame = self.view.bounds;
}

@end
