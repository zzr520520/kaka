TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = Runner
ARCHS = arm64 arm64e

TWEAK_NAME = KakaVoicePro
KakaVoicePro_FILES = Tweak.xm tweetnacl.c
KakaVoicePro_CFLAGS = -fobjc-arc
KakaVoicePro_FRAMEWORKS = UIKit Foundation AVFoundation AudioToolbox CoreAudio Security
KakaVoicePro_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
