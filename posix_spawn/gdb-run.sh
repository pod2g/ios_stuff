#/bin/bash
posix_spawn $* &
gdb -p $!
