TARGET := iphone:clang:latest:7.0
INSTALL_TARGET_PROCESSES = Reddit RedditApp

ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = RedditSideloadFix

$(TWEAK_NAME)_FILES = Tweak.x fishhook/fishhook.c
$(TWEAK_NAME)_CFLAGS = -fobjc-arc
_CODESIGN_IPA = 0

include $(THEOS_MAKE_PATH)/tweak.mk
