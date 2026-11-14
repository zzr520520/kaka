// ============================================================
// KakaVoicePro —— Theos 工程入口
//
// 说明：本工程不使用 Logos 的 %hook 语法，全部 hook 都在
// KakaVoicePro.m 里用 fishhook（C 函数）与 method_setImplementation
// （Objective-C 方法）完成，并在文件末尾通过
//
//     __attribute__((constructor)) static void kp_entry(void)
//
// 在 dylib 被加载时自动执行。因此本文件不需要任何 %hook / %ctor 段，
// 只需把实现编进同一个翻译单元。
// ============================================================

#import "KakaVoicePro.m"
