//
//  AppDelegate.m
//

#import "AppDelegate.h"
#import "RootViewController.h"
#import "KFKernel.h"
#import <AVFoundation/AVFoundation.h>

// UIBackgroundTaskInvalid is 0; static initializer requires a compile-time
// constant, and the UIKit extern const is not. Use 0 directly.
static UIBackgroundTaskIdentifier g_bgTask = 0;

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.rootViewController = [[RootViewController alloc] init];
    [self.window makeKeyAndVisible];

    // Audio background keepalive — configure once at launch
    NSError *err = nil;
    [[AVAudioSession sharedInstance] setCategory:AVAudioSessionCategoryPlayback
                                       withOptions:AVAudioSessionCategoryOptionMixWithOthers
                                             error:&err];
    if (err) {
        NSLog(@"[KFLog] AVAudioSession setCategory failed: %@", err);
    }
    [[AVAudioSession sharedInstance] setActive:YES error:&err];
    if (err) {
        NSLog(@"[KFLog] AVAudioSession setActive failed: %@", err);
    }

    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    // App is about to move from active to inactive state (incoming call, SMS, etc.)
    // Exploit state is kernel-persistent; nothing to tear down here.
    NSLog(@"[KFLog] applicationWillResignActive");
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    NSLog(@"[KFLog] applicationDidEnterBackground");

    // End any previous stale background task first
    if (g_bgTask != 0) {
        [[UIApplication sharedApplication] endBackgroundTask:g_bgTask];
        g_bgTask = 0;
    }

    // Start a new background task to keep exploit state alive a bit longer.
    // Combined with silent audio playback (in RootViewController), this
    // provides robust background keep-alive for kernel logging.
    // AppDelegate is a process-lifetime singleton, no retain cycle risk.
    g_bgTask = [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"KFLogKeepalive"
                                                           expirationHandler:^{
        if (g_bgTask != 0) {
            [[UIApplication sharedApplication] endBackgroundTask:g_bgTask];
            g_bgTask = 0;
        }
    }];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    NSLog(@"[KFLog] applicationWillEnterForeground");

    // Re-activate audio session in case it was interrupted while backgrounded
    NSError *err = nil;
    [[AVAudioSession sharedInstance] setActive:YES
                                   withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation
                                         error:&err];
    if (err) {
        NSLog(@"[KFLog] Foreground AVAudioSession reactivate failed: %@", err);
    }
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    NSLog(@"[KFLog] applicationDidBecomeActive");

    // End background task if we started one — no longer needed once active
    if (g_bgTask != 0) {
        [[UIApplication sharedApplication] endBackgroundTask:g_bgTask];
        g_bgTask = 0;
    }
}

- (void)applicationWillTerminate:(UIApplication *)application {
    NSLog(@"[KFLog] applicationWillTerminate — running KFShutdown to prevent panic");

    // Clean up background task
    if (g_bgTask != 0) {
        [[UIApplication sharedApplication] endBackgroundTask:g_bgTask];
        g_bgTask = 0;
    }

    // Restore socket reference counts so kernel does not panic on exit.
    // KFShutdown() is idempotent and safe even if KFInit never ran.
    KFShutdown();
}

- (void)applicationDidReceiveMemoryWarning:(UIApplication *)application {
    NSLog(@"[KFLog] applicationDidReceiveMemoryWarning");
    // Kernel R/W primitives are memory-light; nothing to free here.
}

@end
