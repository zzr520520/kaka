// ============================================================
// KakaVoicePro.m —— 占位骨架实现（SCAFFOLD）
//
// 说明：入口 Tweak.xm 只做 #import "KakaVoicePro.m"，真正的
// deliverPCM / Mixer processPCM hook 实现文件未随入口一起提供。
// 本文件仅用于打通 Theos + CI 构建链路，加载后只写一行日志，
// 不做任何音频处理。拿到真实实现后直接覆盖本文件即可。
// ============================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static NSString *KP_LOG_PATH(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [dir stringByAppendingPathComponent:@"KakaVoicePro.log"];
}

static void KPLog(NSString *fmt, ...) {
    @autoreleasepool {
        va_list ap;
        va_start(ap, fmt);
        NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);

        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"MM-dd HH:mm:ss.SSS";
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [df stringFromDate:[NSDate date]], msg];

        NSString *path = KP_LOG_PATH();
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:path]) {
            [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
            if (fh) {
                [fh seekToEndOfFile];
                [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile];
            }
        }
        NSLog(@"[KakaVoicePro] %@", msg);
    }
}

__attribute__((constructor)) static void kp_entry(void) {
    KPLog(@"[KakaVoicePro] scaffold loaded (bundle=%@ pid=%d)",
          [[NSBundle mainBundle] bundleIdentifier] ?: @"?",
          (int)getpid());
}
