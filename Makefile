CC=gcc
LD=ld
#BTI=-fcf-protection=full
BTI=
CFLAGS=-c -Wall -O2 -std=c11 -pedantic $(BTI)

all:
	$(CC) $(CFLAGS) inject.c
	$(CC) inject.o -o inject -ldl
	$(CC) $(CFLAGS) -fPIC dso-test.c
	$(LD) -shared -o dso-test.so dso-test.o

clean:
	rm -rf *.o

