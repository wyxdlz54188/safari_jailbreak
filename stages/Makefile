IOS := -Oz -arch arm64 -mios-version-min=12.0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.1.sdk

TIME_SAVED_OBJS := $(patsubst %.m,%.o,$(wildcard time_saved/*.m)) \
                   $(patsubst %.c,%.o,$(wildcard time_saved/*.c))

stages: stage1.o stage2.o $(TIME_SAVED_OBJS)
	clang ${IOS} $^ -shared -o $@ -bind_at_load \
		-fno-stack-protector -fobjc-arc -fmodules -framework IOKit -lc++
	strip -u -r -s exports.txt stages

%.o: %.m common.h
	clang -c ${IOS} $< -o $@ -fno-stack-protector -fobjc-arc -fmodules

%.o: %.c
	clang -c ${IOS} $< -o $@ -fno-stack-protector -fmodules

%.o: %.cpp
	clang -c ${IOS} $< -o $@ -fno-stack-protector -fmodules

.PHONY: clean
clean:
	rm -f *.o *.dylib time_saved/*.o
