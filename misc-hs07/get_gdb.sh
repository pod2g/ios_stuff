#!/bin/sh

GDBPATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/libexec/gdb/gdb-arm-apple-darwin
lipo -thin armv7 $GDBPATH -output gdb
codesign -f -s - --entitlements entitlements_debugger.plist gdb