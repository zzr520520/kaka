TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = Runner
ARCHS = arm64 arm64e

TWEAK_NAME = KakaVoicePro
KakaVoicePro_FILES = Tweak.xm
KakaVoicePro_CFLAGS = -fobjc-arc
KakaVoicePro_FRAMEWORKS = UIKit Foundation AVFoundation AudioToolbox CoreAudio

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
