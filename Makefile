#CFLAGS = -g -std=c99 -Wall -pedantic
#LDFLAGS = -lelf
CC = gcc
CFLAGS = -std=gnu99 -Wall -pedantic -Wextra -O2 -g
LDFLAGS = -lelf
PREFIX = /usr/local

all: patch-for-any-cpu

install: all
	install -D -m 755 -s patch-for-any-cpu ${DESTDIR}${PREFIX}/bin/patch-for-any-cpu

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/patch-for-any-cpu

clean:
	rm -f patch-for-any-cpu *.o tags
