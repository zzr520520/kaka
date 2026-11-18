TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = Runner
ARCHS = arm64 arm64e

TWEAK_NAME = KakaVoicePro
# 直接用 .m 作为翻译单元（原实现不带 Logos 语法，用 C/ObjC 编译才不会被 C++ 严格模式挡住）
KakaVoicePro_FILES = KakaVoicePro.m tweetnacl.c
KakaVoicePro_CFLAGS = -fobjc-arc -include kp_prefix.h
KakaVoicePro_FRAMEWORKS = UIKit Foundation AVFoundation AudioToolbox CoreAudio Security
KakaVoicePro_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
