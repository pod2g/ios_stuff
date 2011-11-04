PLATFORM=/Developer/Platforms/iPhoneOS.platform
SDKVER=4.3
SDK=$(PLATFORM)/Developer/SDKs/iPhoneOS$(SDKVER).sdk
CC=$(PLATFORM)/Developer/usr/bin/gcc-4.2
LD=$(PLATFORM)/Developer/usr/bin/ld
AS=$(PLATFORM)/Developer/usr/bin/as

LDFLAGS=-arch armv6 -ios_version_min 4.3.1 -L$(SDK)/usr/lib -L$(SDK)/usr/lib/system -lc -lcrt1.o
CCFLAGS=-c -O3 -arch armv6 -mthumb -isysroot=$(SDK) -I./include -I$(SDK)/usr/include

all:
	$(CC) $(CCFLAGS) -o main.o main.c
	$(LD) $(LDFLAGS) -o posix_spawn main.o
	rm main.o
	ldid -S posix_spawn
clean:
	rm -f posix_spawn
