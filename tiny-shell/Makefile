PLATFORM=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform
SDKVER=5.1
SDK=$(PLATFORM)/Developer/SDKs/iPhoneOS$(SDKVER).sdk
CC=$(PLATFORM)/Developer/usr/bin/gcc

CCFLAGS=-arch armv7 -isysroot $(SDK)

tiny-shell: main.c
	$(CC) $(CCFLAGS) -o $@ $^
	codesign -fs "iPhone Developer" $@
