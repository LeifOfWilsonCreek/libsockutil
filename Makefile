all: libsockutil.a lookup

libsockutil.a: sockutil.o
	ar -rc libsockutil.a sockutil.o
	ranlib libsockutil.a

sockutil.o: sockutil.h sockutil.c
	$(CC) -O2 -Wall -fpic -c sockutil.c

lookup: lookup.c libsockutil.a
	$(CC) -O2 -Wall -o lookup lookup.c libsockutil.a

install: all
	install -m 0644 -o root -g wheel sockutil.h /usr/include
	install -m 0644 -o root -g wheel libsockutil.a /usr/lib
	install -m 0755 -o root -g wheel lookup /usr/local/bin

clean:
	rm -f libsockutil.a sockutil.o lookup *.core core
