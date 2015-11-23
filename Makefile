CC=gcc
CFLAGS=-std=gnu99 -c

default:
	@echo "Please specify an architecture to build from the following list:"
	@echo "  linux_amd64"
	@echo "  linux_386"

linux_amd64:
	mkdir -p lib/linux/amd64/static lib/linux/amd64/dynamic
	$(CC) $(CFLAGS) -m64 src/linux.c -o linux_amd64.o
	ar -rc lib/linux/amd64/static/libgoacl.a res/linux/amd64/*.o linux_amd64.o
	ar -rc lib/linux/amd64/dynamic/libgoacl.a linux_amd64.o
	cp res/linux/amd64/libacl.so lib/linux/amd64/dynamic/
	cp res/linux/amd64/libattr.so lib/linux/amd64/dynamic

linux_386:
	mkdir -p lib/linux/386/static lib/linux/386/dynamic
	$(CC) $(CFLAGS) -m32 src/linux.c -o linux_386.o
	ar -rc lib/linux/386/static/libgoacl.a res/linux/386/*.o linux_386.o
	ar -rc lib/linux/386/dynamic/libgoacl.a linux_386.o
	cp res/linux/386/libacl.so lib/linux/386/dynamic
	cp res/linux/386/libattr.so lib/linux/386/dynamic

clean:
	rm *.o