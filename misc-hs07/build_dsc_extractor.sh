#!/bin/sh

if [ ! -f dyld-210.2.3.tar.gz ]
then
    curl -O http://opensource.apple.com/tarballs/dyld/dyld-210.2.3.tar.gz
fi

if [ ! -d dyld-210.2.3 ]
then
    tar xvf dyld-210.2.3.tar.gz
fi

patch dyld-210.2.3/launch-cache/dsc_extractor.cpp dsc_extractor.patch
clang++ -o dsc_extractor dyld-210.2.3/launch-cache/dsc_extractor.cpp dyld-210.2.3/launch-cache/dsc_iterator.cpp

#./dsc_extractor dyld_shared_cache_armv7 dylibs_folder/
