GO_EASY_ON_ME = 1
DEBUG = 0
FINALPACKAGE = 1

THEOS_DEVICE_IP = 127.0.0.1 -p 2222

TARGET := iphone:clang:12.4:12.4
# THEOS_PACKAGE_SCHEME=rootful

ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TOOL_NAME = stage3

stage3_FILES = main.m krw.c alert.c rejailbreak.m
stage3_CFLAGS = -fobjc-arc -Oz
stage3_CODESIGN_FLAGS = -Sentitlements.plist
stage3_FRAMEWORKS = Foundation IOKit
stage3_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
