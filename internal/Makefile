CC=gcc
CFLAGS=-std=gnu99 -c

default:
	@echo "Please specify an architecture to build from the following list:"
	@echo "  linux_amd64"
	@echo "  linux_386"
	@echo "  all"

all: linux_amd64 linux_386

linux_amd64:
	mkdir -p lib/linux/amd64/static lib/linux/amd64/dynamic

	# libgoacl
	$(CC) $(CFLAGS) -m64 src/linux.c -o libgoacl_linux_amd64.o
	@# ar -rc sometimes fails to overwrite properly, so just to be safe
	rm -f lib/linux/amd64/static/libgoacl.a lib/linux/amd64/dynamic/libgoacl.a
	ar -rc lib/linux/amd64/static/libgoacl.a res/linux/amd64/*.o libgoacl_linux_amd64.o
	ar -rc lib/linux/amd64/dynamic/libgoacl.a libgoacl_linux_amd64.o
	cp res/linux/amd64/libacl.so lib/linux/amd64/dynamic/
	cp res/linux/amd64/libattr.so lib/linux/amd64/dynamic

	# libgogrpunix
	$(CC) $(CFLAGS) -m64 src/go-grp-unix.c -o libgogrpunix_linux_amd64.o
	@# ar -rc sometimes fails to overwrite properly, so just to be safe
	rm -f lib/linux/amd64/static/libgogrpunix.a
	ar -rc lib/linux/amd64/static/libgogrpunix.a libgogrpunix_linux_amd64.o
	cp lib/linux/amd64/static/libgogrpunix.a lib/linux/amd64/dynamic/libgogrpunix.a

linux_386:
	mkdir -p lib/linux/386/static lib/linux/386/dynamic

	# libgoacl
	$(CC) $(CFLAGS) -m32 src/linux.c -o libgoacl_linux_386.o
	@# ar -rc sometimes fails to overwrite properly, so just to be safe
	rm -f lib/linux/386/static/libgoacl.a lib/linux/386/dynamic/libgoacl.a
	ar -rc lib/linux/386/static/libgoacl.a res/linux/386/*.o libgoacl_linux_386.o
	ar -rc lib/linux/386/dynamic/libgoacl.a libgoacl_linux_386.o
	cp res/linux/386/libacl.so lib/linux/386/dynamic
	cp res/linux/386/libattr.so lib/linux/386/dynamic

	# libgogrpunix
	$(CC) $(CFLAGS) -m32 src/go-grp-unix.c -o libgogrpunix_linux_386.o
	@# ar -rc sometimes fails to overwrite properly, so just to be safe
	rm -f lib/linux/386/static/libgogrpunix.a
	ar -rc lib/linux/386/static/libgogrpunix.a libgogrpunix_linux_386.o
	cp lib/linux/386/static/libgogrpunix.a lib/linux/386/dynamic/libgogrpunix.a

clean:
	rm *.o