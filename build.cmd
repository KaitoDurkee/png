echo off
set CC="cl"
set $CFLAGS="/W4" #"/O2 /W4"
%CC% %CFLAGS% png.c