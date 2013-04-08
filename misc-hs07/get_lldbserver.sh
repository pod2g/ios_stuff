#!/bin/sh

DEVDISK="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/6.1 (10B141)/DeveloperDiskImage.dmg"

hdiutil attach $DEVDISK
cp /Volumes/DeveloperDiskImage/usr/bin/debugserver .
codesign -f -s - --entitlements entitlements_debugger.plist debugserver
hdiutil detach /Volumes/DeveloperDiskImage/
