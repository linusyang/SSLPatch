include theos/makefiles/common.mk

IPHONE_ARCHS = armv7 arm64
TWEAK_NAME = SSLPatch_CVE-2014-1266
SSLPatch_CVE-2014-1266_FILES = Tweak.xm internal.c
SSLPatch_CVE-2014-1266_LIBRARIES = substrate
SSLPatch_CVE-2014-1266_FRAMEWORKS = Security

include $(THEOS_MAKE_PATH)/tweak.mk

stage::
	plutil -convert binary1 "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/$(TWEAK_NAME).plist"
