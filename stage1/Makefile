
SCFLAGS = -arch arm64 -Wall -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -c -Os -fno-stack-protector -fno-unwind-tables -fno-exceptions 

all:
	clang stage1.c -o stage1.o $(SCFLAGS)
	ld stage1.o -o stage1 -dylib -lSystem -syslibroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
	(echo GLOB && xxd -i stage1) | grep -v len > stage1_sc.h