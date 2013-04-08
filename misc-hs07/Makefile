SDKVER?=5.1
ARCH?=armv7
SDK=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS$(SDKVER).sdk/
CC=clang -arch $(ARCH) -isysroot $(SDK) 
CFLAGS=-Wall -O3 -I.
LDFLAGS=-framework CoreFoundation -framework IOKit -framework Security
LDFLAGS+= -miphoneos-version-min=4.0
CODESIGN=codesign -s - --entitlements entitlements.plist

%.dylib: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^
	$(CODESIGN) $@

%: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	$(CODESIGN) $@
