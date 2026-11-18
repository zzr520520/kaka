KakaVoicePro v29.8 源码包
=========================

版本：v29.8（2026-11-15 构建）
dylib SHA-256：fbe9c4918facc72a61c673adbfdee0c189f1008b2c6466e86e8622b821e45203

文件清单
--------
KakaVoicePro.m          主源码（4396 行，全部逻辑都在这一个文件里）
tweetnacl.c / .h        Ed25519 验签（授权用）
fishhook.c / .h         fishhook（符号重绑定）
kp_aes.h                AES/白盒授权辅助
kp_rsa.h                RSA 授权校验
build.sh                Linux 交叉编译脚本
KakaVoicePro_v29.8.dylib  已编译产物（arm64，可直接用）

编译
----
    chmod +x build.sh
    ./build.sh

需要 iOS SDK，默认路径 /workspace/work/sdks/iPhoneOS15.6.sdk，可用环境变量覆盖：

    SDK=/path/to/iPhoneOS15.6.sdk ./build.sh

如果换机器没有 ld64.lld，把 build.sh 里最后那个 -fuse-ld=... 参数删掉，
改用系统自带的链接器即可（macOS 上直接 clang 就能编）。

本版要点
--------
1. 强声霸麦（Priority Loudness）开关：100Hz 高通、2.2k/3.4k 各 +4dB、
   压缩 2ms/80ms、向上提拉上限 5.0x、RMS 目标 -8dBFS。默认关闭。
2. 远端屏蔽三档：100% / 20%（只压低不静音）/ 0%（全屏蔽），
   hook 挂在 RTCMediaStreamTrack 父类，0.5s 巡检自动覆盖新上麦的轨。
3. APM 硬锁：AGC1/AGC2/NS/瞬态抑制/高通 恒 NO；AEC 条件关。
4. 防掐断：roomCaptureGateEnabled 恒 NO、speakerphoneEchoCancellation 条件关、
   willEnableEngine 在霸麦/屏蔽开启时强传 vp=NO。
5. [mixproc] 打印真实出口电平（outPeak / outRMS），可与 probe 行对比。

注意
----
APM 的 AGC/NS/瞬态抑制是全局硬锁，不受开关控制，底噪会明显变大，属预期。
new 版本注意：`g_priorityLoud` 是霸麦开关，`g_shieldRemote` 是全屏蔽，
`g_shieldLowOnly` 是 20% 档 —— 如需二次开发请沿用这三个名字。
