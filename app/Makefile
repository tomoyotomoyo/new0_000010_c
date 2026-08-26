TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

THEOS ?= $(HOME)/theos

export PACKAGE_FORMAT = ipa
ARCHS := arm64 arm64e

THEOS ?= $(HOME)/theos

ifeq ($(wildcard ./KFInit.c),)
  KF_DIR := ..
else
  KF_DIR := .
endif

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = KFLog

KFLog_FILES = \
	main.m \
	AppDelegate.m \
	RootViewController.m \
	KFLogFilter.c \
	$(KF_DIR)/KFInit.c \
	$(KF_DIR)/kexploit/kexploit_opa334.m \
	$(KF_DIR)/kexploit/krw.m \
	$(KF_DIR)/kexploit/kutils.m \
	$(KF_DIR)/kexploit/offsets.m \
	$(KF_DIR)/kexploit/vnode.m \
	$(KF_DIR)/sandbox/sandbox_escape.m \
	$(KF_DIR)/apfs/apfs_own.m \
	$(KF_DIR)/kpf/patchfinder.m \
	$(KF_DIR)/xpf/xpf.c \
	$(KF_DIR)/xpf/common.c \
	$(KF_DIR)/xpf/decompress.c \
	$(KF_DIR)/xpf/bad_recovery.c \
	$(KF_DIR)/xpf/non_ppl.c \
	$(KF_DIR)/xpf/ppl.c \
	$(KF_DIR)/utils/file.c \
	$(KF_DIR)/utils/hexdump.c \
	$(KF_DIR)/utils/process.c

KFLog_FILES += \
	$(KF_DIR)/choma/DyldSharedCache.c \
	$(KF_DIR)/choma/MachO.c \
	$(KF_DIR)/choma/Fat.c \
	$(KF_DIR)/choma/CSBlob.c \
	$(KF_DIR)/choma/CodeDirectory.c \
	$(KF_DIR)/choma/PatchFinder.c \
	$(KF_DIR)/choma/PatchFinder_arm64.c \
	$(KF_DIR)/choma/arm64.c \
	$(KF_DIR)/choma/Entitlements.c \
	$(KF_DIR)/choma/MemoryStream.c \
	$(KF_DIR)/choma/BufferedStream.c \
	$(KF_DIR)/choma/FileStream.c \
	$(KF_DIR)/choma/Base64.c \
	$(KF_DIR)/choma/DER.c \
	$(KF_DIR)/choma/Host.c \
	$(KF_DIR)/choma/Util.c \
	$(KF_DIR)/choma/MachOLoadCommand.c

KFLog_FRAMEWORKS = UIKit WebKit Foundation
KFLog_PRIVATE_FRAMEWORKS = IOKit

KFLog_CFLAGS = \
	-I$(KF_DIR) \
	-I$(KF_DIR)/kexploit \
	-I$(KF_DIR)/sandbox \
	-I$(KF_DIR)/apfs \
	-I$(KF_DIR)/kpf \
	-I$(KF_DIR)/xpf \
	-I$(KF_DIR)/choma \
	-I$(KF_DIR)/utils \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-format \
	-Wno-incompatible-pointer-types \
	-Wno-deprecated-declarations \
	-Wno-error

KFLog_LDFLAGS = -Wl,-segalign,4000

include $(THEOS_MAKE_PATH)/application.mk

after-install::
	@echo "=== KFLog IPA built ==="
	@ls -la $(THEOS_OBJ_DIR)/*.ipa 2>/dev/null || ls -la $(THEOS_OBJ_DIR)/*.app 2>/dev/null || true
